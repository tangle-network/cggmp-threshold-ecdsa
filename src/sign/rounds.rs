/*
    CGGMP Threshold ECDSA

    Copyright 2022 by Webb Technologies.

    This file is part of cggmp library
    (https://github.com/webb-tools/cggmp-threshold-ecdsa)

    cggmp-threshold-ecdsa is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/webb-tools/cggmp/blob/main/LICENSE>
*/
use std::{collections::HashMap, marker::PhantomData};

use curv::{
    arithmetic::{traits::*, Modulo},
    elliptic::curves::{Point, Scalar, Secp256k1},
    BigInt,
};
use round_based::{
    containers::{push::Push, BroadcastMsgs, BroadcastMsgsStore},
    Msg,
};
use sha2::Sha256;

use paillier::*;

use crate::{
    presign::{PresigningOutput, PresigningTranscript, DEFAULT_ENCRYPTION_KEY},
    ErrorType, NoOfflineStageErrorData, ProofVerificationErrorData,
};
use thiserror::Error;
use tss_core::utilities::{
    sample_relatively_prime_integer, RingPedersenParams,
};
use tss_core::zkproof::aff_g::{PiAffGProof, PiAffGStatement, PiAffGWitness};
use tss_core::zkproof::dec::{PiDecProof, PiDecStatement, PiDecWitness};
use tss_core::zkproof::mul_star::{
    PiMulStarProof, PiMulStarStatement, PiMulStarWitness,
};

use zeroize::Zeroize;

use super::{
    SigningBroadcastMessage1, SigningIdentifiableAbortMessage, SigningOutput,
    SSID,
};

use super::state_machine::{Round0Messages, Round1Messages};

pub struct Round0 {
    pub ssid: SSID<Secp256k1>,
    pub l: usize, // This is the number of presignings to run in parallel
    pub m: BigInt,
    pub presigning_data: HashMap<
        u16,
        (PresigningOutput<Secp256k1>, PresigningTranscript<Secp256k1>),
    >,
}

impl Round0 {
    pub fn proceed<O>(mut self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<Box<SigningBroadcastMessage1<Secp256k1>>>>,
    {
        // If there is a record for (l,...)
        if let Some((presigning_output, presigning_transcript)) =
            self.presigning_data.get_mut(&(self.l as u16))
        {
            // r = R projected onto x axis
            let r = presigning_output.R.x_coord().unwrap_or_else(BigInt::zero);
            // sigma_i = k*m + r*chi
            let sigma_i = presigning_output
                .k_i
                .mul(&self.m)
                .add(&r.mul(&presigning_output.chi_i))
                .mod_floor(&self.ssid.q);
            let body = SigningBroadcastMessage1 {
                ssid: self.ssid.clone(),
                i: self.ssid.X.i,
                sigma_i: sigma_i.clone(),
            };
            output.push(Msg {
                sender: self.ssid.X.i,
                receiver: None,
                body: Box::new(body),
            });
            // Erase output from memory
            presigning_output.zeroize();
            Ok(Round1 {
                ssid: self.ssid.clone(),
                i: self.ssid.X.i,
                presigning_transcript: presigning_transcript.clone(),
                m: self.m,
                r,
                sigma_i,
            })
        } else {
            let error_data = NoOfflineStageErrorData { l: self.l };
            Err(SignError::NoOfflineStageError(ErrorType {
                error_type: "mul".to_string(),
                bad_actors: vec![],
                data: bincode::serialize(&error_data).unwrap(),
            }))
        }
    }
    pub fn is_expensive(&self) -> bool {
        false
    }
}

pub struct Round1 {
    pub ssid: SSID<Secp256k1>,
    pub i: u16,
    pub m: BigInt,
    pub r: BigInt,
    pub sigma_i: BigInt,
    pub presigning_transcript: PresigningTranscript<Secp256k1>,
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<SigningBroadcastMessage1<Secp256k1>>,
        mut output: O,
    ) -> Result<Round2>
    where
        O: Push<Msg<Box<Option<SigningIdentifiableAbortMessage<Secp256k1>>>>>,
    {
        // Mapping from j to sigma_j
        let mut sigmas: HashMap<u16, BigInt> = HashMap::new();
        for msg in input.into_vec() {
            sigmas.insert(msg.i, msg.sigma_i);
        }
        let sigma: BigInt = sigmas
            .values()
            .fold(self.sigma_i.clone(), |acc, x| acc.add(x))
            .mod_floor(&self.ssid.q);

        // Verify (r, sigma) is a valid signature
        // sigma^{-1}
        let sigma_inv = BigInt::mod_inv(&sigma, &self.ssid.q).unwrap();
        // m*sigma^{-1}
        let m_sigma_inv = self.m.mul(&sigma_inv);
        // r*sigma^{-1}
        let r_sigma_inv = self.r.mul(&sigma_inv);
        let g = Point::<Secp256k1>::generator();
        let X = self.ssid.X.public_key();
        let x_projection = ((g * Scalar::from_bigint(&m_sigma_inv))
            + (X * Scalar::from_bigint(&r_sigma_inv)))
        .x_coord()
        .unwrap_or_else(BigInt::zero);

        if self.r == x_projection {
            let signing_output = SigningOutput {
                ssid: self.ssid.clone(),
                m: self.m,
                r: self.r,
                sigma,
            };
            output.push(Msg {
                sender: self.ssid.X.i,
                receiver: None,
                body: Box::new(None),
            });
            Ok(Round2 {
                ssid: self.ssid,
                output: Some(signing_output),
            })
        } else {
            // (l,j) to proof for D_j_i
            let mut proofs_D_hat_j_i: HashMap<
                (u16, u16),
                PiAffGProof<Secp256k1, Sha256>,
            > = HashMap::new();

            // (l,j) to statement for D_j_i
            let mut statements_D_hat_j_i: HashMap<
                (u16, u16),
                PiAffGStatement<Secp256k1, Sha256>,
            > = HashMap::new();

            self.ssid
                .P
                .iter()
                .zip(self.ssid.P.iter())
                .for_each(|(j, l)| {
                    if *j != self.ssid.X.i && j != l {
                        let D_hat_j_i = self
                            .presigning_transcript
                            .D_hat_j
                            .get(&self.ssid.X.i)
                            .unwrap()
                            .clone();

                        // F_hat_j_i = enc_i(beta_hat_i_j, r_hat_i_j)
                        let F_hat_j_i = self
                            .presigning_transcript
                            .F_hat_j
                            .get(&self.ssid.X.i)
                            .unwrap()
                            .clone();

                        let witness_D_hat_j_i = PiAffGWitness::new(
                            self.presigning_transcript.secrets.x_i.clone(),
                            self.presigning_transcript
                                .beta_hat_i
                                .get(j)
                                .unwrap_or(&BigInt::zero())
                                .clone(),
                            self.presigning_transcript
                                .s_hat_i
                                .get(j)
                                .unwrap_or(&BigInt::zero())
                                .clone(),
                            self.presigning_transcript
                                .r_hat_i
                                .get(j)
                                .unwrap_or(&BigInt::zero())
                                .clone(),
                        );
                        let statement_D_hat_j_i = PiAffGStatement {
                            RPParam: RingPedersenParams {
                                N: self
                                    .presigning_transcript
                                    .N_hats
                                    .get(l)
                                    .unwrap_or(&BigInt::zero())
                                    .clone(),
                                s: self
                                    .presigning_transcript
                                    .S
                                    .get(l)
                                    .unwrap_or(&BigInt::zero())
                                    .clone(),
                                t: self
                                    .presigning_transcript
                                    .T
                                    .get(l)
                                    .unwrap_or(&BigInt::zero())
                                    .clone(),
                            },
                            N0: self.presigning_transcript.secrets.ek.n.clone(),
                            N1: self
                                .presigning_transcript
                                .eks
                                .get(j)
                                .unwrap_or(&DEFAULT_ENCRYPTION_KEY())
                                .n
                                .clone(),
                            NN0: self
                                .presigning_transcript
                                .secrets
                                .ek
                                .nn
                                .clone(),
                            NN1: self
                                .presigning_transcript
                                .eks
                                .get(j)
                                .unwrap_or(&DEFAULT_ENCRYPTION_KEY())
                                .nn
                                .clone(),
                            C: D_hat_j_i,
                            D: self
                                .presigning_transcript
                                .K
                                .get(j)
                                .unwrap_or(&BigInt::zero())
                                .clone(),
                            Y: F_hat_j_i,
                            X: Point::<Secp256k1>::generator().as_point()
                                * Scalar::from_bigint(
                                    &self.presigning_transcript.secrets.x_i,
                                ),
                            ek_prover: self
                                .presigning_transcript
                                .secrets
                                .ek
                                .clone(),
                            ek_verifier: self
                                .presigning_transcript
                                .eks
                                .get(j)
                                .unwrap_or(&DEFAULT_ENCRYPTION_KEY())
                                .clone(),
                            phantom: PhantomData,
                        };
                        let proof_D_hat_j_i = PiAffGProof::prove(
                            &witness_D_hat_j_i,
                            &statement_D_hat_j_i,
                        );
                        proofs_D_hat_j_i.insert((*l, *j), proof_D_hat_j_i);
                        statements_D_hat_j_i
                            .insert((*l, *j), statement_D_hat_j_i);
                    }
                });

            // mul* H_hat_i proof
            let H_hat_i_randomness = sample_relatively_prime_integer(
                &self.presigning_transcript.secrets.ek.n,
            );
            let H_hat_i: BigInt = Paillier::encrypt_with_chosen_randomness(
                &self.presigning_transcript.secrets.ek,
                RawPlaintext::from(
                    self.presigning_transcript
                        .k_i
                        .mul(&self.presigning_transcript.secrets.x_i),
                ),
                &Randomness::from(H_hat_i_randomness.clone()),
            )
            .into();
            let witness_H_hat_i = PiMulStarWitness::new(
                self.presigning_transcript.secrets.x_i.clone(),
                self.presigning_transcript.rho_i.mul(&H_hat_i_randomness),
            );

            let X_i = Point::<Secp256k1>::generator()
                * Scalar::from_bigint(&self.presigning_transcript.secrets.x_i);

            let mut proof_H_hat_i: HashMap<
                u16,
                PiMulStarProof<Secp256k1, Sha256>,
            > = HashMap::new();
            let mut statement_H_hat_i: HashMap<
                u16,
                PiMulStarStatement<Secp256k1, Sha256>,
            > = HashMap::new();

            self.ssid.P.iter().for_each(|l| {
                if *l != self.ssid.X.i {
                    let statement_H_hat_l_i = PiMulStarStatement {
                        N0: self.presigning_transcript.secrets.ek.n.clone(),
                        NN0: self.presigning_transcript.secrets.ek.nn.clone(),
                        C: self.presigning_transcript.K_i.clone(),
                        D: H_hat_i.clone(),
                        X: X_i.clone(),
                        RPParams: RingPedersenParams {
                            N: self
                                .presigning_transcript
                                .N_hats
                                .get(l)
                                .unwrap_or(&BigInt::zero())
                                .clone(),
                            s: self
                                .presigning_transcript
                                .S
                                .get(l)
                                .unwrap_or(&BigInt::zero())
                                .clone(),
                            t: self
                                .presigning_transcript
                                .T
                                .get(l)
                                .unwrap_or(&BigInt::zero())
                                .clone(),
                        },
                        phantom: PhantomData,
                    };

                    statement_H_hat_i.insert(*l, statement_H_hat_l_i.clone());

                    proof_H_hat_i.insert(
                        *l,
                        PiMulStarProof::<Secp256k1, Sha256>::prove(
                            &witness_H_hat_i,
                            &statement_H_hat_l_i,
                        ),
                    );
                }
            });

            // dec proof
            let s_hat_j_i = BigInt::zero();
            let ciphertext = H_hat_i;
            let ciphertext_randomness = H_hat_i_randomness;
            self.ssid.P.iter().for_each(|j| {
                if *j != self.ssid.X.i {
                    ciphertext
                        .mul(
                            self.presigning_transcript
                                .D_hat_i
                                .get(j)
                                .unwrap_or(&BigInt::zero()),
                        )
                        .mul(
                            self.presigning_transcript
                                .F_hat_j
                                .get(&self.ssid.X.i)
                                .unwrap(),
                        );
                    ciphertext_randomness.mul(&s_hat_j_i).mul(
                        self.presigning_transcript
                            .r_hat_i
                            .get(j)
                            .unwrap_or(&BigInt::zero()),
                    );
                }
            });

            BigInt::mod_pow(
                &ciphertext,
                &self.r,
                &self.presigning_transcript.secrets.ek.nn,
            );
            ciphertext.mul(&BigInt::mod_pow(
                &self.presigning_transcript.K_i,
                &self.m,
                &self.presigning_transcript.secrets.ek.nn,
            ));
            BigInt::mod_pow(
                &ciphertext_randomness,
                &self.r,
                &self.presigning_transcript.secrets.ek.nn,
            );
            ciphertext_randomness.mul(&BigInt::mod_pow(
                &self.presigning_transcript.K_i,
                &self.m,
                &self.presigning_transcript.secrets.ek.nn,
            ));

            let witness_sigma_i = PiDecWitness::new(
                Paillier::decrypt(
                    &self.presigning_transcript.secrets.dk,
                    RawCiphertext::from(ciphertext.clone()),
                )
                .into(),
                ciphertext_randomness,
            );

            // l to statement
            let mut statement_sigma_i: HashMap<
                u16,
                PiDecStatement<Secp256k1, Sha256>,
            > = HashMap::new();

            // l to proof
            let mut proof_sigma_i: HashMap<u16, PiDecProof<Secp256k1, Sha256>> =
                HashMap::new();

            self.ssid.P.iter().for_each(|l| {
                if *l != self.ssid.X.i {
                    let statement_sigma_l_i = PiDecStatement {
                        RPParams: RingPedersenParams {
                            N: self
                                .presigning_transcript
                                .N_hats
                                .get(l)
                                .unwrap_or(&BigInt::zero())
                                .clone(),
                            s: self
                                .presigning_transcript
                                .S
                                .get(l)
                                .unwrap_or(&BigInt::zero())
                                .clone(),
                            t: self
                                .presigning_transcript
                                .T
                                .get(l)
                                .unwrap_or(&BigInt::zero())
                                .clone(),
                        },
                        N0: self.presigning_transcript.secrets.ek.n.clone(),
                        NN0: self.presigning_transcript.secrets.ek.nn.clone(),
                        C: ciphertext.clone(),
                        x: self.sigma_i.clone(),
                        ek_prover: self
                            .presigning_transcript
                            .secrets
                            .ek
                            .clone(),
                        phantom: PhantomData,
                    };

                    statement_sigma_i.insert(*l, statement_sigma_l_i.clone());

                    proof_sigma_i.insert(
                        *l,
                        PiDecProof::<Secp256k1, Sha256>::prove(
                            &witness_sigma_i,
                            &statement_sigma_l_i,
                        ),
                    );
                }
            });

            let body = Some(SigningIdentifiableAbortMessage {
                i: self.ssid.X.i,
                proofs_D_hat_j_i,
                statements_D_hat_j_i,
                proof_H_hat_i,
                statement_H_hat_i,
                proof_sigma_i,
                statement_sigma_i,
            });
            output.push(Msg {
                sender: self.ssid.X.i,
                receiver: None,
                body: Box::new(body),
            });
            Ok(Round2 {
                ssid: self.ssid,
                output: None,
            })
        }
    }

    pub fn is_expensive(&self) -> bool {
        false
    }

    pub fn expects_messages(i: u16, n: u16) -> Round0Messages {
        BroadcastMsgsStore::new(i, n)
    }
}

pub struct Round2 {
    ssid: SSID<Secp256k1>,
    output: Option<SigningOutput<Secp256k1>>,
}

impl Round2 {
    pub fn proceed(
        self,
        input: BroadcastMsgs<
            Option<SigningIdentifiableAbortMessage<Secp256k1>>,
        >,
    ) -> Result<Option<SigningOutput<Secp256k1>>> {
        if self.output.is_some() {
            Ok(Some(self.output.unwrap()))
        } else {
            for msg in input.into_vec() {
                let msg = msg.unwrap();
                // si stands for sender index
                let si = msg.i;
                // Check D_hat_i_j proofs
                let mut vec_D_hat_si_j_proof_bad_actors: Vec<usize> = vec![];
                self.ssid.P.iter().for_each(|j| {
                    if *j != self.ssid.X.i {
                        let D_hat_si_j_proof = msg
                            .proofs_D_hat_j_i
                            .get(&(self.ssid.X.i, *j))
                            .unwrap();

                        let statement_D_hat_si_j = msg
                            .statements_D_hat_j_i
                            .get(&(self.ssid.X.i, *j))
                            .unwrap();

                        if PiAffGProof::<Secp256k1, Sha256>::verify(
                            D_hat_si_j_proof,
                            statement_D_hat_si_j,
                        )
                        .is_err()
                        {
                            vec_D_hat_si_j_proof_bad_actors.push(*j as usize);
                        }
                    }
                });

                if !vec_D_hat_si_j_proof_bad_actors.is_empty() {
                    let error_data = ProofVerificationErrorData {
                        proof_symbol: "D_hat_si_j".to_string(),
                        verifying_party: self.ssid.X.i,
                    };
                    return Err(SignError::ProofVerificationError(ErrorType {
                        error_type: "aff-g".to_string(),
                        bad_actors: vec_D_hat_si_j_proof_bad_actors,
                        data: bincode::serialize(&error_data).unwrap(),
                    }));
                }
                // Check H_j proofs
                let proof_H_hat_si =
                    msg.proof_H_hat_i.get(&self.ssid.X.i).unwrap();
                let statement_H_hat_si =
                    msg.statement_H_hat_i.get(&self.ssid.X.i).unwrap();

                if PiMulStarProof::verify(proof_H_hat_si, statement_H_hat_si)
                    .is_err()
                {
                    let error_data = ProofVerificationErrorData {
                        proof_symbol: "H_hat_si".to_string(),
                        verifying_party: self.ssid.X.i,
                    };
                    return Err(SignError::ProofVerificationError(ErrorType {
                        error_type: "mul".to_string(),
                        bad_actors: vec![si.into()],
                        data: bincode::serialize(&error_data).unwrap(),
                    }));
                }
                // Check delta_si_proof
                let proof_sigma_si =
                    msg.proof_sigma_i.get(&self.ssid.X.i).unwrap();
                let statement_sigma_si =
                    msg.statement_sigma_i.get(&self.ssid.X.i).unwrap();

                if PiDecProof::verify(proof_sigma_si, statement_sigma_si)
                    .is_err()
                {
                    let error_data = ProofVerificationErrorData {
                        proof_symbol: "sigma_si".to_string(),
                        verifying_party: self.ssid.X.i,
                    };
                    return Err(SignError::ProofVerificationError(ErrorType {
                        error_type: "dec-q".to_string(),
                        bad_actors: vec![si.into()],
                        data: bincode::serialize(&error_data).unwrap(),
                    }));
                }
            }
            Ok(None)
        }
    }

    pub fn is_expensive(&self) -> bool {
        false
    }
    pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
        BroadcastMsgsStore::new(i, n)
    }
}

type Result<T> = std::result::Result<T, SignError>;

#[derive(Error, Debug, Clone)]
pub enum SignError {
    #[error("Proof Verification Error")]
    ProofVerificationError(ErrorType),

    #[error("No Offline Stage Error")]
    NoOfflineStageError(ErrorType),
}
