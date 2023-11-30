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

use super::{
    IdentifiableAbortBroadcastMessage, PreSigningP2PMessage1,
    PreSigningP2PMessage2, PreSigningP2PMessage3, PreSigningSecrets,
    PresigningOutput, PresigningTranscript, DEFAULT_ENCRYPTION_KEY, SSID,
};
use crate::{
    utilities::{
        aff_g::{
            PaillierAffineOpWithGroupComInRangeProof,
            PaillierAffineOpWithGroupComInRangeStatement,
            PaillierAffineOpWithGroupComInRangeWitness,
        },
        dec_q::{
            PaillierDecryptionModQProof, PaillierDecryptionModQStatement,
            PaillierDecryptionModQWitness,
        },
        log_star::{
            KnowledgeOfExponentPaillierEncryptionProof,
            KnowledgeOfExponentPaillierEncryptionStatement,
            KnowledgeOfExponentPaillierEncryptionWitness,
        },
        mul::{PaillierMulProof, PaillierMulStatement, PaillierMulWitness},
    },
    ErrorType, ProofVerificationErrorData,
};
use curv::{
    arithmetic::{traits::*, Modulo, Samplable},
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{Point, Scalar, Secp256k1},
    BigInt,
};
use tss_core::security_level::L_PRIME;
use tss_core::utilities::sample_relatively_prime_integer;
use tss_core::zkproof::enc::{
    PaillierEncryptionInRangeProof, PaillierEncryptionInRangeStatement,
    PaillierEncryptionInRangeWitness,
};

use paillier::{
    Add, Decrypt, EncryptWithChosenRandomness, EncryptionKey, Mul, Paillier,
    Randomness, RawCiphertext, RawPlaintext,
};
use round_based::{
    containers::{
        push::Push, BroadcastMsgs, BroadcastMsgsStore, P2PMsgs, P2PMsgsStore,
    },
    Msg,
};

use sha2::Sha256;
use thiserror::Error;

use super::state_machine::{
    Round0Messages, Round1Messages, Round2Messages, Round3Messages,
};

pub struct Round0 {
    pub ssid: SSID<Secp256k1>,
    pub secrets: PreSigningSecrets,
    pub S: HashMap<u16, BigInt>,
    pub T: HashMap<u16, BigInt>,
    pub N_hats: HashMap<u16, BigInt>,
    pub l: usize, // This is the number of presignings to run in parallel
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<Box<PreSigningP2PMessage1<Secp256k1>>>>,
    {
        // k_i <- F_q
        let k_i = BigInt::sample_below(&self.ssid.q);
        // gamma_i <- F_q
        let gamma_i = BigInt::sample_below(&self.ssid.q);
        // rho_i <- Z*_{N_i}
        let rho_i = sample_relatively_prime_integer(&self.secrets.ek.n);
        // nu_i <- Z*_{N_i}
        let nu_i = sample_relatively_prime_integer(&self.secrets.ek.n);
        // G_i = enc_i(gamma_i; nu_i)
        let G_i: BigInt = Paillier::encrypt_with_chosen_randomness(
            &self.secrets.ek,
            RawPlaintext::from(gamma_i.clone()),
            &Randomness::from(nu_i.clone()),
        )
        .into();
        // K_i = enc_i(k_i; rho_i)
        let K_i: BigInt = Paillier::encrypt_with_chosen_randomness(
            &self.secrets.ek,
            RawPlaintext::from(k_i.clone()),
            &Randomness(rho_i.clone()),
        )
        .into();
        let witness_psi_0_j_i =
            PaillierEncryptionInRangeWitness::new(k_i.clone(), rho_i.clone());

        for j in self.ssid.P.iter() {
            if *j != self.ssid.X.i {
                let statement_psi_0_j_i = PaillierEncryptionInRangeStatement {
                    N0: self.secrets.ek.n.clone(),
                    NN0: self.secrets.ek.nn.clone(),
                    K: K_i.clone(),
                    RPParam: tss_core::utilities::RingPedersenParams {
                        N: self
                            .N_hats
                            .get(j)
                            .unwrap_or(&BigInt::zero())
                            .clone(),
                        s: self.S.get(j).unwrap_or(&BigInt::zero()).clone(),
                        t: self.T.get(j).unwrap_or(&BigInt::zero()).clone(),
                    },
                    phantom: PhantomData,
                };
                let psi_0_j_i =
                    PaillierEncryptionInRangeProof::<Secp256k1, Sha256>::prove(
                        &witness_psi_0_j_i,
                        &statement_psi_0_j_i,
                    );

                let body = PreSigningP2PMessage1 {
                    ssid: self.ssid.clone(),
                    i: self.ssid.X.i,
                    K_i: K_i.clone(),
                    G_i: G_i.clone(),
                    psi_0_j_i,
                    enc_j_statement: statement_psi_0_j_i,
                    ek: self.secrets.ek.clone(),
                };
                output.push(Msg {
                    sender: self.ssid.X.i,
                    receiver: Some(*j),
                    body: Box::new(body),
                });
            }
        }
        Ok(Round1 {
            ssid: self.ssid,
            secrets: self.secrets,
            gamma_i,
            k_i,
            nu_i,
            rho_i,
            G_i,
            K_i,
            S: self.S,
            T: self.T,
            N_hats: self.N_hats,
        })
    }
    pub fn is_expensive(&self) -> bool {
        false
    }
}

pub struct Round1 {
    pub ssid: SSID<Secp256k1>,
    pub secrets: PreSigningSecrets,
    pub gamma_i: BigInt,
    pub k_i: BigInt,
    pub nu_i: BigInt,
    pub rho_i: BigInt,
    pub G_i: BigInt,
    pub K_i: BigInt,
    pub S: HashMap<u16, BigInt>,
    pub T: HashMap<u16, BigInt>,
    pub N_hats: HashMap<u16, BigInt>,
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: P2PMsgs<PreSigningP2PMessage1<Secp256k1>>,
        mut output: O,
    ) -> Result<Round2>
    where
        O: Push<Msg<Box<PreSigningP2PMessage2<Secp256k1>>>>,
    {
        // Since x_i is a (t,n) share of x, we need to transform it to a (t,t+1)
        // share omega_i using the appropriate lagrangian coefficient
        // lambda_{i,S} as defined by GG18 and GG20. We then use omega_i
        // in place of x_i for the rest of the protocol. Ref: https://eprint.iacr.org/2021/060.pdf (Section 1.2.8)
        // Ref: https://eprint.iacr.org/2019/114.pdf (Section 4.2)
        // Ref: https://eprint.iacr.org/2020/540.pdf (Section 3.2)
        let lambda_i_s =
            VerifiableSS::<Secp256k1, Sha256>::map_share_to_new_params(
                &self.ssid.X.vss_scheme.parameters,
                self.ssid.X.i - 1,
                &self.ssid.P.iter().map(|i| i - 1).collect::<Vec<u16>>(),
            );
        let omega_i = BigInt::mod_mul(
            &lambda_i_s.to_bigint(),
            &self.secrets.x_i,
            &self.ssid.q,
        );

        let mut K: HashMap<u16, BigInt> = HashMap::new();
        let mut G: HashMap<u16, BigInt> = HashMap::new();
        let mut eks: HashMap<u16, EncryptionKey> = HashMap::new();
        // Verify P2P Messages
        for msg in input.into_vec() {
            // j
            let j = msg.i;
            // Insert K_j
            K.insert(j, msg.K_i);
            // Insert G_j
            G.insert(j, msg.G_i);
            // Insert j's Paillier encryption key
            eks.insert(j, msg.ek);
            let psi_0_i_j = msg.psi_0_j_i;
            let enc_i_statement = msg.enc_j_statement;
            // Verify psi_0_i_j proof
            if PaillierEncryptionInRangeProof::<Secp256k1, Sha256>::verify(
                &psi_0_i_j,
                &enc_i_statement,
            )
            .is_err()
            {
                let error_data = ProofVerificationErrorData {
                    proof_symbol: "psi_0_i_j".to_string(),
                    verifying_party: self.ssid.X.i,
                };
                return Err(PresignError::ProofVerificationError(ErrorType {
                    error_type: "enc".to_string(),
                    bad_actors: vec![j.into()],
                    data: bincode::serialize(&error_data).unwrap(),
                }));
            }
        }

        // Gamma_i = g^{gamma_i}
        let Gamma_i = Point::<Secp256k1>::generator().as_point()
            * Scalar::from_bigint(&self.gamma_i);
        // {beta, beta_hat, r, r_hat, s, s_hat}_i will store mapping from j to
        // {beta, beta_hat, r, r_hat, s, s_hat}_i_j.
        let mut beta_i: HashMap<u16, BigInt> = HashMap::new();
        let mut beta_hat_i: HashMap<u16, BigInt> = HashMap::new();
        let mut r_i: HashMap<u16, BigInt> = HashMap::new();
        let mut r_hat_i: HashMap<u16, BigInt> = HashMap::new();
        let mut s_i: HashMap<u16, BigInt> = HashMap::new();
        let mut s_hat_i: HashMap<u16, BigInt> = HashMap::new();
        let mut D_j: HashMap<u16, BigInt> = HashMap::new();
        let mut F_j: HashMap<u16, BigInt> = HashMap::new();
        let mut D_hat_j: HashMap<u16, BigInt> = HashMap::new();
        let mut F_hat_j: HashMap<u16, BigInt> = HashMap::new();

        for j in self.ssid.P.iter() {
            if j != &self.ssid.X.i {
                // r_i_j <- Z_{N_j}
                let r_i_j = BigInt::sample_below(
                    &eks.get(j).unwrap_or(&DEFAULT_ENCRYPTION_KEY()).n,
                );
                r_i.insert(*j, r_i_j.clone());
                // s_i_j <- Z_{N_j}
                let s_i_j = BigInt::sample_below(
                    &eks.get(j).unwrap_or(&DEFAULT_ENCRYPTION_KEY()).n,
                );
                s_i.insert(*j, s_i_j.clone());
                // r_hat_i_j <- Z_{N_j}
                let r_hat_i_j = BigInt::sample_below(
                    &eks.get(j).unwrap_or(&DEFAULT_ENCRYPTION_KEY()).n,
                );
                r_hat_i.insert(*j, r_hat_i_j.clone());
                // s_hat_i_j <- Z_{N_j}
                let s_hat_i_j = BigInt::sample_below(
                    &eks.get(j).unwrap_or(&DEFAULT_ENCRYPTION_KEY()).n,
                );
                s_hat_i.insert(*j, s_hat_i_j.clone());
                let upper = BigInt::pow(&BigInt::from(2), L_PRIME as u32);
                let lower = BigInt::from(-1).mul(&upper);
                // beta_i_j <- [-2^L_PRIME, 2^L_PRIME]
                let beta_i_j = BigInt::sample_range(&lower, &upper);
                beta_i.insert(*j, beta_i_j.clone());
                // beta_hat_i_j <- [-2^L_PRIME, 2^L_PRIME]
                let beta_hat_i_j = BigInt::sample_range(&lower, &upper);
                beta_hat_i.insert(*j, beta_hat_i_j.clone());

                let encrypt_minus_beta_i_j =
                    Paillier::encrypt_with_chosen_randomness(
                        eks.get(j).unwrap_or(&DEFAULT_ENCRYPTION_KEY()),
                        RawPlaintext::from(
                            BigInt::from(-1).mul(&beta_i_j.clone()),
                        ),
                        &Randomness::from(s_i_j.clone()),
                    );
                // D_j_i =  (gamma_i [.] K_j ) ⊕ enc_j(-beta_i_j; s_i_j) where
                // [.] is Paillier multiplication
                let D_j_i: BigInt = Paillier::add(
                    eks.get(j).unwrap_or(&DEFAULT_ENCRYPTION_KEY()),
                    Paillier::mul(
                        eks.get(j).unwrap_or(&DEFAULT_ENCRYPTION_KEY()),
                        RawCiphertext::from(
                            K.get(j).unwrap_or(&BigInt::zero()),
                        ),
                        RawPlaintext::from(self.gamma_i.clone()),
                    ),
                    encrypt_minus_beta_i_j,
                )
                .into();

                D_j.insert(*j, D_j_i.clone());

                // F_j_i = enc_i(beta_i_j, r_i_j)
                let F_j_i: BigInt = Paillier::encrypt_with_chosen_randomness(
                    &self.secrets.ek,
                    // To compute F_j_i, beta_i_j is NOT multiplied by -1 in
                    // the paper (see Figure 7, Round 2 in
                    // the paper), but that makes Π^aff-g ZK proof
                    // verification fail (see Figure 15 in the paper). This is
                    // because Π^aff-g states:
                    // - Y = (1 + N_1)^y ρ_y ^ N_1
                    // - D = C^x (1 + N_0)^y ρ ^ N_0
                    // And from Figure 7, Round 2 we can see that:
                    // - x = gamma_i
                    // - y = beta_i_j
                    // - ρ = s_i_j
                    // - ρ_y = r_i_j
                    // - Y = F_j_i i.e (1 + N_j)^{beta_i_j} r_i_j ^ {N_j}
                    // :- (1) enc_j(beta_i_j, r_i_j)
                    // - C = K_j
                    // - D = D_j_i i.e K ^ {gamma_i} (1 + N_i)^{beta_i_j} s_i_j
                    //   ^ {N_i}
                    // :- (2) D ≡ gamma_i ⊙ K_j ⊕ enc_i(beta_i_j, s_i_j)
                    //
                    // From (1) and (2) we can see the mismatch between Π^aff-g
                    // (see Figure 15) and pre-signing
                    // definitions (see Figure 7, Round 2) i.e the Π^aff-g
                    // verification will fail unless we
                    // apply (or don't apply) negation uniformly to beta_i_j
                    // before encrypting it to generate F_j_i and D_j_i.
                    //
                    // We have 2 options to solve the sign mismatch:
                    // - (A). We can redefine y as negative beta_i_j, update
                    //   F_j_i to encrypt a negative beta_i_j, and leave D_j_i
                    //   unchanged.
                    // - (B). We can redefine D_j_i to encrypt a positive
                    //   beta_i_j, leave y and F_j_i unchanged, and modify
                    //   Figure 7, Round 3 to subtract beta_i_j instead of
                    //   adding it when computing delta_i.
                    //
                    // We choose option (A) since it entails less modifications
                    // to the overall protocol (i.e all
                    // changes are performed in Round 2).
                    //
                    // NOTE: A similar transformation has to be applied to the
                    // "hat" variants (i.e beta_hat_i_j,
                    // F_hat_j_i, D_hat_j_i)  as well. (see also https://en.wikipedia.org/wiki/Paillier_cryptosystem#Homomorphic_properties)
                    RawPlaintext::from(BigInt::from(-1).mul(&beta_i_j.clone())),
                    &Randomness::from(r_i_j.clone()),
                )
                .into();

                F_j.insert(*j, F_j_i.clone());

                // Compute D_hat_j_i
                let encrypt_minus_beta_hat_i_j =
                    Paillier::encrypt_with_chosen_randomness(
                        eks.get(j).unwrap_or(&DEFAULT_ENCRYPTION_KEY()),
                        RawPlaintext::from(BigInt::from(-1).mul(&beta_hat_i_j)),
                        &Randomness::from(s_hat_i_j.clone()),
                    );
                // D_hat_j_i =  (x_i [.] K_j ) ⊕ enc_j(-beta_hat_i_j; s_hat_i_j)
                // where [.] is Paillier multiplication
                let D_hat_j_i: BigInt = Paillier::add(
                    eks.get(j).unwrap_or(&DEFAULT_ENCRYPTION_KEY()),
                    Paillier::mul(
                        eks.get(j).unwrap_or(&DEFAULT_ENCRYPTION_KEY()),
                        RawCiphertext::from(
                            K.get(j).unwrap_or(&BigInt::zero()),
                        ),
                        // We use omega_i in place of x_i, see doc on omega_i
                        // definition for explanation.
                        RawPlaintext::from(omega_i.clone()),
                    ),
                    encrypt_minus_beta_hat_i_j,
                )
                .into();

                D_hat_j.insert(*j, D_hat_j_i.clone());

                // F_hat_j_i = enc_i(beta_hat_i_j, r_hat_i_j)
                let F_hat_j_i: BigInt =
                    Paillier::encrypt_with_chosen_randomness(
                        &self.secrets.ek,
                        // See reasoning documented under F_j_i for why we
                        // multiply beta_hat_i_j by -1
                        // before encrypting it.
                        RawPlaintext::from(
                            BigInt::from(-1).mul(&beta_hat_i_j.clone()),
                        ),
                        &Randomness::from(r_hat_i_j.clone()),
                    )
                    .into();

                F_hat_j.insert(*j, F_hat_j_i.clone());

                // psi_j_i
                let witness_psi_j_i =
                    PaillierAffineOpWithGroupComInRangeWitness::new(
                        self.gamma_i.clone(),
                        // See reasoning documented under F_j_i for why we
                        // multiply beta_i_j by -1.
                        BigInt::from(-1).mul(&beta_i_j.clone()),
                        s_i_j.clone(),
                        r_i_j.clone(),
                    );
                let statement_psi_j_i =
                    PaillierAffineOpWithGroupComInRangeStatement {
                        S: self.S.get(j).unwrap_or(&BigInt::zero()).clone(),
                        T: self.T.get(j).unwrap_or(&BigInt::zero()).clone(),
                        N_hat: self
                            .N_hats
                            .get(j)
                            .unwrap_or(&BigInt::zero())
                            .clone(),
                        N0: eks
                            .get(j)
                            .unwrap_or(&DEFAULT_ENCRYPTION_KEY())
                            .n
                            .clone(),
                        N1: self.secrets.ek.n.clone(),
                        NN0: eks
                            .get(j)
                            .unwrap_or(&DEFAULT_ENCRYPTION_KEY())
                            .nn
                            .clone(),
                        NN1: self.secrets.ek.nn.clone(),
                        C: K.get(j).unwrap_or(&BigInt::zero()).clone(),
                        D: D_j_i.clone(),
                        Y: F_j_i.clone(),
                        X: Gamma_i.clone(),
                        ek_prover: self.secrets.ek.clone(),
                        ek_verifier: eks
                            .get(j)
                            .unwrap_or(&DEFAULT_ENCRYPTION_KEY())
                            .clone(),
                        phantom: PhantomData,
                    };
                let psi_j_i = PaillierAffineOpWithGroupComInRangeProof::<
                    Secp256k1,
                    Sha256,
                >::prove(
                    &witness_psi_j_i, &statement_psi_j_i
                );

                // psi_hat_j_i
                let witness_psi_hat_j_i =
                    PaillierAffineOpWithGroupComInRangeWitness::new(
                        // We use omega_i in place of x_i, see doc on omega_i
                        // definition for explanation.
                        omega_i.clone(),
                        // See reasoning documented under F_j_i for why we
                        // multiply beta_hat_i_j by -1.
                        BigInt::from(-1).mul(&beta_hat_i_j.clone()),
                        s_hat_i_j.clone(),
                        r_hat_i_j.clone(),
                    );
                let statement_psi_hat_j_i =
                    PaillierAffineOpWithGroupComInRangeStatement {
                        S: self.S.get(j).unwrap_or(&BigInt::zero()).clone(),
                        T: self.T.get(j).unwrap_or(&BigInt::zero()).clone(),
                        N_hat: self
                            .N_hats
                            .get(j)
                            .unwrap_or(&BigInt::zero())
                            .clone(),
                        N0: eks
                            .get(j)
                            .unwrap_or(&DEFAULT_ENCRYPTION_KEY())
                            .n
                            .clone(),
                        N1: self.secrets.ek.n.clone(),
                        NN0: eks
                            .get(j)
                            .unwrap_or(&DEFAULT_ENCRYPTION_KEY())
                            .nn
                            .clone(),
                        NN1: self.secrets.ek.nn.clone(),
                        C: K.get(j).unwrap_or(&BigInt::zero()).clone(),
                        D: D_hat_j_i.clone(),
                        Y: F_hat_j_i.clone(),
                        // We use omega_i in place of x_i, see doc on omega_i
                        // definition for explanation.
                        X: Point::<Secp256k1>::generator().as_point()
                            * Scalar::from_bigint(&omega_i),
                        ek_prover: self.secrets.ek.clone(),
                        ek_verifier: eks
                            .get(j)
                            .unwrap_or(&DEFAULT_ENCRYPTION_KEY())
                            .clone(),
                        phantom: PhantomData,
                    };
                let psi_hat_j_i = PaillierAffineOpWithGroupComInRangeProof::<
                    Secp256k1,
                    Sha256,
                >::prove(
                    &witness_psi_hat_j_i,
                    &statement_psi_hat_j_i,
                );

                // psi_prime_j_i
                let witness_psi_prime_j_i =
                    KnowledgeOfExponentPaillierEncryptionWitness::new(
                        self.gamma_i.clone(),
                        self.nu_i.clone(),
                    );
                let statement_psi_prime_j_i =
                    KnowledgeOfExponentPaillierEncryptionStatement {
                        N0: self.secrets.ek.n.clone(),
                        NN0: self.secrets.ek.nn.clone(),
                        C: self.G_i.clone(),
                        X: Gamma_i.clone(),
                        // g is not always the secp256k1 generator, so we have
                        // to pass it explicitly.
                        // See [`KnowledgeOfExponentPaillierEncryptionStatement`] inline doc for g field
                        // for details.
                        g: Point::generator().to_point(),
                        s: self.S.get(j).unwrap_or(&BigInt::zero()).clone(),
                        t: self.T.get(j).unwrap_or(&BigInt::zero()).clone(),
                        N_hat: self
                            .N_hats
                            .get(j)
                            .unwrap_or(&BigInt::zero())
                            .clone(),
                        phantom: PhantomData,
                    };
                let psi_prime_j_i = KnowledgeOfExponentPaillierEncryptionProof::<
                    Secp256k1,
                    Sha256,
                >::prove(
                    &witness_psi_prime_j_i,
                    &statement_psi_prime_j_i,
                );

                // Send Message
                let body = PreSigningP2PMessage2 {
                    ssid: self.ssid.clone(),
                    i: self.ssid.X.i,
                    Gamma_i: Gamma_i.clone(),
                    D_j_i: D_j_i.clone(),
                    F_j_i: F_j_i.clone(),
                    D_hat_j_i: D_hat_j_i.clone(),
                    F_hat_j_i: F_hat_j_i.clone(),
                    psi_j_i: psi_j_i.clone(),
                    statement_psi_j_i,
                    psi_hat_j_i,
                    statement_psi_hat_j_i,
                    psi_prime_j_i,
                    statement_psi_prime_j_i,
                };
                output.push(Msg {
                    sender: self.ssid.X.i,
                    receiver: Some(*j),
                    body: Box::new(body),
                });
            }
        }
        Ok(Round2 {
            ssid: self.ssid,
            secrets: self.secrets,
            omega_i,
            eks,
            gamma_i: self.gamma_i,
            k_i: self.k_i,
            Gamma_i,
            nu_i: self.nu_i,
            rho_i: self.rho_i,
            G_i: self.G_i,
            K_i: self.K_i,
            G,
            K,
            beta_i,
            beta_hat_i,
            r_i,
            r_hat_i,
            s_i,
            s_hat_i,
            D_j,
            D_hat_j,
            F_j,
            F_hat_j,
            S: self.S,
            T: self.T,
            N_hats: self.N_hats,
        })
    }

    pub fn is_expensive(&self) -> bool {
        false
    }

    pub fn expects_messages(i: u16, n: u16) -> Round0Messages {
        P2PMsgsStore::new(i, n)
    }
}

pub struct Round2 {
    pub ssid: SSID<Secp256k1>,
    pub secrets: PreSigningSecrets,
    pub omega_i: BigInt,
    pub eks: HashMap<u16, EncryptionKey>,
    pub gamma_i: BigInt,
    pub Gamma_i: Point<Secp256k1>,
    pub k_i: BigInt,
    pub nu_i: BigInt,
    pub rho_i: BigInt,
    pub G_i: BigInt,
    pub K_i: BigInt,
    pub G: HashMap<u16, BigInt>,
    pub K: HashMap<u16, BigInt>,
    pub beta_i: HashMap<u16, BigInt>,
    pub beta_hat_i: HashMap<u16, BigInt>,
    pub r_i: HashMap<u16, BigInt>,
    pub r_hat_i: HashMap<u16, BigInt>,
    pub s_i: HashMap<u16, BigInt>,
    pub s_hat_i: HashMap<u16, BigInt>,
    pub D_j: HashMap<u16, BigInt>,
    pub D_hat_j: HashMap<u16, BigInt>,
    pub F_j: HashMap<u16, BigInt>,
    pub F_hat_j: HashMap<u16, BigInt>,
    pub S: HashMap<u16, BigInt>,
    pub T: HashMap<u16, BigInt>,
    pub N_hats: HashMap<u16, BigInt>,
}

impl Round2 {
    pub fn proceed<O>(
        self,
        input: P2PMsgs<PreSigningP2PMessage2<Secp256k1>>,
        mut output: O,
    ) -> Result<Round3>
    where
        O: Push<Msg<Box<PreSigningP2PMessage3<Secp256k1>>>>,
    {
        let mut D_i: HashMap<u16, BigInt> = HashMap::new();
        let mut D_hat_i: HashMap<u16, BigInt> = HashMap::new();
        let mut F_i: HashMap<u16, BigInt> = HashMap::new();
        let mut F_hat_i: HashMap<u16, BigInt> = HashMap::new();
        let mut Gammas: HashMap<u16, Point<Secp256k1>> = HashMap::new();

        // Shift alpha_i_j to the interval {-N/2,...,N/2} (if necessary) as
        // defined in Section 4.1 of the paper.
        let shift_into_plus_minus_n_by_2_interval =
            |mut value: BigInt| -> BigInt {
                if value > self.secrets.ek.n.div_floor(&BigInt::from(2)) {
                    value -= &self.secrets.ek.n;
                }
                value
            };

        for msg in input.into_vec() {
            // j
            let j = msg.i;
            // Insert D_i_j
            D_i.insert(j, msg.D_j_i);
            // Insert D_hat_i_j
            D_hat_i.insert(j, msg.D_hat_j_i);
            // Insert F_i_j
            F_i.insert(j, msg.F_j_i);
            // Insert F_hat_i_j
            F_hat_i.insert(j, msg.F_hat_j_i);
            // Insert Gamma_j
            Gammas.insert(j, msg.Gamma_i);
            // Verify first aff-g
            let psi_i_j = msg.psi_j_i;
            let statement_psi_i_j = msg.statement_psi_j_i;
            // Verify psi_i_j
            if PaillierAffineOpWithGroupComInRangeProof::<Secp256k1, Sha256>::verify(
				&psi_i_j,
				&statement_psi_i_j,
			)
			.is_err()
			{
				let error_data = ProofVerificationErrorData {
					proof_symbol: "psi_i_j".to_string(),
					verifying_party: self.ssid.X.i,
				};
				return Err(PresignError::ProofVerificationError(ErrorType {
					error_type: "aff-g".to_string(),
					bad_actors: vec![j.into()],
					data: bincode::serialize(&error_data).unwrap(),
				}))
			}

            // Verify psi_hat_i_j
            let psi_hat_i_j = msg.psi_hat_j_i;
            let statement_psi_hat_i_j = msg.statement_psi_hat_j_i;
            if PaillierAffineOpWithGroupComInRangeProof::<Secp256k1, Sha256>::verify(
				&psi_hat_i_j,
				&statement_psi_hat_i_j,
			)
			.is_err()
			{
				let error_data = ProofVerificationErrorData {
					proof_symbol: "psi_hat_i_j".to_string(),
					verifying_party: self.ssid.X.i,
				};
				return Err(PresignError::ProofVerificationError(ErrorType {
					error_type: "aff-g".to_string(),
					bad_actors: vec![j.into()],
					data: bincode::serialize(&error_data).unwrap(),
				}))
			}

            // Verify psi_prime_i_j
            let psi_prime_i_j = msg.psi_prime_j_i;
            let statement_psi_prime_i_j = msg.statement_psi_prime_j_i;
            if KnowledgeOfExponentPaillierEncryptionProof::<Secp256k1, Sha256>::verify(
				&psi_prime_i_j,
				&statement_psi_prime_i_j,
			)
			.is_err()
			{
				let error_data = ProofVerificationErrorData {
					proof_symbol: "psi_prime_i_j".to_string(),
					verifying_party: self.ssid.X.i,
				};
				return Err(PresignError::ProofVerificationError(ErrorType {
					error_type: "log*".to_string(),
					bad_actors: vec![j.into()],
					data: bincode::serialize(&error_data).unwrap(),
				}))
			}
        }

        // Gamma = Prod_j (Gamma_j)
        let Gamma =
            Gammas.values().fold(self.Gamma_i.clone(), |acc, x| acc + x);

        // Delta = Gamma^{k_i}
        let Delta_i = Gamma.clone() * Scalar::from_bigint(&self.k_i);

        // {alpha, alpha_hat}_i will store mapping from j to {alpha,
        // alpha_hat}_i_j
        let mut alpha_i: HashMap<u16, BigInt> = HashMap::new();
        let mut alpha_hat_i: HashMap<u16, BigInt> = HashMap::new();
        for j in self.ssid.P.iter() {
            if j != &self.ssid.X.i {
                alpha_i.insert(
                    *j,
                    shift_into_plus_minus_n_by_2_interval(
                        Paillier::decrypt(
                            &self.secrets.dk,
                            RawCiphertext::from(
                                D_i.get(j).unwrap_or(&BigInt::zero()),
                            ),
                        )
                        .into(),
                    )
                    .mod_floor(&self.ssid.q),
                );
                alpha_hat_i.insert(
                    *j,
                    shift_into_plus_minus_n_by_2_interval(
                        Paillier::decrypt(
                            &self.secrets.dk,
                            RawCiphertext::from(
                                D_hat_i.get(j).unwrap_or(&BigInt::zero()),
                            ),
                        )
                        .into(),
                    )
                    .mod_floor(&self.ssid.q),
                );
            }
        }

        // Sum alpha_i_j's
        let sum_of_alphas =
            alpha_i.values().fold(BigInt::zero(), |acc, x| acc.add(x));

        // Sum alpha_hat_i_j's
        let sum_of_alpha_hats = alpha_hat_i
            .values()
            .fold(BigInt::zero(), |acc, x| acc.add(x));

        // Sum beta_i_j's
        let sum_of_betas = self
            .beta_i
            .values()
            .fold(BigInt::zero(), |acc, x| acc.add(x));

        // Sum beta_hat_i_j's
        let sum_of_beta_hats = self
            .beta_hat_i
            .values()
            .fold(BigInt::zero(), |acc, x| acc.add(x));

        // delta_i = gamma_i * k_i + sum of alpha_i_j's + sum of beta_i_j's mod
        // q
        let delta_i = BigInt::mod_add(
            &BigInt::mod_mul(&self.gamma_i, &self.k_i, &self.ssid.q),
            &BigInt::mod_add(&sum_of_alphas, &sum_of_betas, &self.ssid.q),
            &self.ssid.q,
        );

        // chi_i = x_i * k_i + sum of alpha_hat_i_j's + sum of beta_hat_i_j's
        let chi_i = BigInt::mod_add(
            // We use omega_i in place of x_i, see doc on omega_i definition
            // (in Round 1) for explanation.
            &BigInt::mod_mul(&self.omega_i, &self.k_i, &self.ssid.q),
            &BigInt::mod_add(
                &sum_of_alpha_hats,
                &sum_of_beta_hats,
                &self.ssid.q,
            ),
            &self.ssid.q,
        );

        for j in self.ssid.P.iter() {
            if j != &self.ssid.X.i.clone() {
                // Compute psi_prime_prime_j_i
                let witness_psi_prime_prime_j_i =
                    KnowledgeOfExponentPaillierEncryptionWitness::new(
                        self.k_i.clone(),
                        self.rho_i.clone(),
                    );

                let statement_psi_prime_prime_j_i =
                    KnowledgeOfExponentPaillierEncryptionStatement {
                        N0: self.secrets.ek.n.clone(),
                        NN0: self.secrets.ek.nn.clone(),
                        C: self.K_i.clone(),
                        X: Delta_i.clone(),
                        // From the Delta_i = Gamma^{k_i} and Πlog∗ stating X =
                        // g^x, Since x = k_i and X =
                        // Delta_i, :- g = Gamma
                        // (see Figure 7, Round 3 and Figure 25 in paper).
                        g: Gamma.clone(),
                        s: self.S.get(j).unwrap_or(&BigInt::zero()).clone(),
                        t: self.T.get(j).unwrap_or(&BigInt::zero()).clone(),
                        N_hat: self
                            .N_hats
                            .get(j)
                            .unwrap_or(&BigInt::zero())
                            .clone(),
                        phantom: PhantomData,
                    };
                let psi_prime_prime_j_i =
                    KnowledgeOfExponentPaillierEncryptionProof::<
                        Secp256k1,
                        Sha256,
                    >::prove(
                        &witness_psi_prime_prime_j_i,
                        &statement_psi_prime_prime_j_i,
                    );

                // Send Message
                let body = PreSigningP2PMessage3 {
                    ssid: self.ssid.clone(),
                    i: self.ssid.X.i,
                    delta_i: delta_i.clone(),
                    Delta_i: Delta_i.clone(),
                    psi_prime_prime_j_i,
                    statement_psi_prime_prime_j_i,
                };
                output.push(Msg {
                    sender: self.ssid.X.i,
                    receiver: Some(*j),
                    body: Box::new(body),
                });
            }
        }
        Ok(Round3 {
            ssid: self.ssid,
            secrets: self.secrets,
            eks: self.eks,
            gamma_i: self.gamma_i,
            Gamma_i: self.Gamma_i,
            Gammas,
            Gamma,
            k_i: self.k_i,
            nu_i: self.nu_i,
            rho_i: self.rho_i,
            G_i: self.G_i,
            K_i: self.K_i,
            G: self.G,
            K: self.K,
            beta_i: self.beta_i,
            beta_hat_i: self.beta_hat_i,
            r_i: self.r_i,
            r_hat_i: self.r_hat_i,
            s_i: self.s_i,
            s_hat_i: self.s_hat_i,
            delta_i,
            chi_i,
            Delta_i,
            D_j: self.D_j,
            D_hat_j: self.D_hat_j,
            F_j: self.F_j,
            F_hat_j: self.F_hat_j,
            D_i,
            D_hat_i,
            F_i,
            F_hat_i,
            alpha_i,
            alpha_hat_i,
            S: self.S,
            T: self.T,
            N_hats: self.N_hats,
        })
    }

    pub fn is_expensive(&self) -> bool {
        false
    }
    pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
        P2PMsgsStore::new(i, n)
    }
}

pub struct Round3 {
    pub ssid: SSID<Secp256k1>,
    pub secrets: PreSigningSecrets,
    pub eks: HashMap<u16, EncryptionKey>,
    pub gamma_i: BigInt,
    pub Gamma_i: Point<Secp256k1>,
    pub Gammas: HashMap<u16, Point<Secp256k1>>,
    pub Gamma: Point<Secp256k1>,
    pub k_i: BigInt,
    pub nu_i: BigInt,
    pub rho_i: BigInt,
    pub G_i: BigInt,
    pub K_i: BigInt,
    pub G: HashMap<u16, BigInt>,
    pub K: HashMap<u16, BigInt>,
    pub beta_i: HashMap<u16, BigInt>,
    pub beta_hat_i: HashMap<u16, BigInt>,
    pub r_i: HashMap<u16, BigInt>,
    pub r_hat_i: HashMap<u16, BigInt>,
    pub s_i: HashMap<u16, BigInt>,
    pub s_hat_i: HashMap<u16, BigInt>,
    pub delta_i: BigInt,
    pub chi_i: BigInt,
    pub Delta_i: Point<Secp256k1>,
    pub D_j: HashMap<u16, BigInt>,
    pub D_hat_j: HashMap<u16, BigInt>,
    pub F_j: HashMap<u16, BigInt>,
    pub F_hat_j: HashMap<u16, BigInt>,
    pub D_i: HashMap<u16, BigInt>,
    pub D_hat_i: HashMap<u16, BigInt>,
    pub F_i: HashMap<u16, BigInt>,
    pub F_hat_i: HashMap<u16, BigInt>,
    pub alpha_i: HashMap<u16, BigInt>,
    pub alpha_hat_i: HashMap<u16, BigInt>,
    pub S: HashMap<u16, BigInt>,
    pub T: HashMap<u16, BigInt>,
    pub N_hats: HashMap<u16, BigInt>,
}

impl Round3 {
    pub fn proceed<O>(
        self,
        input: P2PMsgs<PreSigningP2PMessage3<Secp256k1>>,
        mut output: O,
    ) -> Result<Round4>
    where
        O: Push<Msg<Box<Option<IdentifiableAbortBroadcastMessage<Secp256k1>>>>>,
    {
        // Mapping from j to delta_j
        let mut deltas: HashMap<u16, BigInt> = HashMap::new();
        // Mapping from j to Delta_j
        let mut Deltas: HashMap<u16, Point<Secp256k1>> = HashMap::new();
        for msg in input.into_vec() {
            // j
            let j = msg.i;
            // Verify psi_prime_prime_i_j
            let psi_prime_prime_i_j = msg.psi_prime_prime_j_i;

            let statement_psi_prime_prime_i_j =
                msg.statement_psi_prime_prime_j_i;

            if KnowledgeOfExponentPaillierEncryptionProof::<Secp256k1, Sha256>::verify(
				&psi_prime_prime_i_j,
				&statement_psi_prime_prime_i_j,
			)
			.is_err()
			{
				let error_data = ProofVerificationErrorData {
					proof_symbol: "psi_prime_prime_i_j".to_string(),
					verifying_party: self.ssid.X.i,
				};
				return Err(PresignError::ProofVerificationError(ErrorType {
					error_type: "log*".to_string(),
					bad_actors: vec![j.into()],
					data: bincode::serialize(&error_data).unwrap(),
				}))
			}

            // Insert into deltas and Deltas
            deltas.insert(j, msg.delta_i);
            Deltas.insert(j, msg.Delta_i);
        }

        // delta = sum of delta_j's
        let delta = deltas
            .values()
            .fold(self.delta_i.clone(), |acc, x| acc.add(x))
            .mod_floor(&self.ssid.q);

        // Compute product of Delta_j's
        let product_of_Deltas =
            Deltas.values().fold(self.Delta_i.clone(), |acc, x| acc + x);

        if product_of_Deltas
            == Point::<Secp256k1>::generator().as_point()
                * Scalar::from_bigint(&delta)
        {
            // R = Gamma^{delta^{-1}}
            let R = self.Gamma.clone()
                * Scalar::from_bigint(
                    &BigInt::mod_inv(&delta, &self.ssid.q).unwrap(),
                );
            let presigning_output = PresigningOutput {
                ssid: self.ssid.clone(),
                R,
                i: self.ssid.X.i,
                k_i: self.k_i.clone(),
                chi_i: self.chi_i.clone(),
            };
            let transcript = PresigningTranscript {
                ssid: self.ssid.clone(),
                secrets: self.secrets,
                eks: self.eks,
                gamma_i: self.gamma_i,
                Gamma_i: self.Gamma_i,
                Gammas: self.Gammas,
                Gamma: self.Gamma,
                k_i: self.k_i,
                nu_i: self.nu_i,
                rho_i: self.rho_i,
                G_i: self.G_i,
                K_i: self.K_i,
                G: self.G,
                K: self.K,
                beta_i: self.beta_i,
                beta_hat_i: self.beta_hat_i,
                r_i: self.r_i,
                r_hat_i: self.r_hat_i,
                s_i: self.s_i,
                s_hat_i: self.s_hat_i,
                delta_i: self.delta_i.clone(),
                chi_i: self.chi_i.clone(),
                Delta_i: self.Delta_i.clone(),
                deltas,
                Deltas,
                delta,
                D_j: self.D_j,
                D_hat_j: self.D_hat_j,
                F_j: self.F_j,
                F_hat_j: self.F_hat_j,
                D_i: self.D_i,
                D_hat_i: self.D_hat_i,
                F_i: self.F_i,
                F_hat_i: self.F_hat_i,
                alpha_i: self.alpha_i,
                alpha_hat_i: self.alpha_hat_i,
                S: self.S,
                T: self.T,
                N_hats: self.N_hats,
            };

            output.push(Msg {
                sender: self.ssid.X.i,
                receiver: None,
                body: Box::new(None),
            });

            Ok(Round4 {
                ssid: self.ssid,
                output: Some(presigning_output),
                transcript: Some(transcript),
            })
        } else {
            // (l,j) to proof for D_j_i
            let mut proofs_D_j_i: HashMap<
                (u16, u16),
                PaillierAffineOpWithGroupComInRangeProof<Secp256k1, Sha256>,
            > = HashMap::new();

            // (l,j) to statement for D_j_i
            let mut statements_D_j_i: HashMap<
                (u16, u16),
                PaillierAffineOpWithGroupComInRangeStatement<Secp256k1, Sha256>,
            > = HashMap::new();

            self.ssid
                .P
                .iter()
                .zip(self.ssid.P.iter())
                .for_each(|(j, l)| {
                    if *j != self.ssid.X.i && j != l {
                        let D_j_i =
                            self.D_j.get(&self.ssid.X.i.clone()).unwrap();

                        // F_j_i = enc_i(beta_i_j, r_i_j)
                        let F_j_i = self.F_j.get(&self.ssid.X.i).unwrap();

                        let witness_D_j_i =
                            PaillierAffineOpWithGroupComInRangeWitness::new(
                                self.gamma_i.clone(),
                                self.beta_i
                                    .get(j)
                                    .unwrap_or(&BigInt::zero())
                                    .clone(),
                                self.s_i
                                    .get(j)
                                    .unwrap_or(&BigInt::zero())
                                    .clone(),
                                self.r_i
                                    .get(j)
                                    .unwrap_or(&BigInt::zero())
                                    .clone(),
                            );
                        let statement_D_j_i =
                            PaillierAffineOpWithGroupComInRangeStatement {
                                S: self
                                    .S
                                    .get(l)
                                    .unwrap_or(&BigInt::zero())
                                    .clone(),
                                T: self
                                    .T
                                    .get(l)
                                    .unwrap_or(&BigInt::zero())
                                    .clone(),
                                N_hat: self
                                    .N_hats
                                    .get(l)
                                    .unwrap_or(&BigInt::zero())
                                    .clone(),
                                N0: self.secrets.ek.n.clone(),
                                N1: self
                                    .eks
                                    .get(j)
                                    .unwrap_or(&DEFAULT_ENCRYPTION_KEY())
                                    .n
                                    .clone(),
                                NN0: self.secrets.ek.nn.clone(),
                                NN1: self
                                    .eks
                                    .get(j)
                                    .unwrap_or(&DEFAULT_ENCRYPTION_KEY())
                                    .nn
                                    .clone(),
                                C: D_j_i.clone(),
                                D: self
                                    .K
                                    .get(j)
                                    .unwrap_or(&BigInt::zero())
                                    .clone(),
                                Y: F_j_i.clone(),
                                X: self.Gamma_i.clone(),
                                ek_prover: self.secrets.ek.clone(),
                                ek_verifier: self
                                    .eks
                                    .get(j)
                                    .unwrap_or(&DEFAULT_ENCRYPTION_KEY())
                                    .clone(),
                                phantom: PhantomData,
                            };
                        let D_j_i_proof =
                            PaillierAffineOpWithGroupComInRangeProof::<
                                Secp256k1,
                                Sha256,
                            >::prove(
                                &witness_D_j_i, &statement_D_j_i
                            );
                        proofs_D_j_i.insert((*l, *j), D_j_i_proof);
                        statements_D_j_i.insert((*l, *j), statement_D_j_i);
                    }
                });

            // H_i proof
            let H_i_randomness: BigInt =
                sample_relatively_prime_integer(&self.secrets.ek.n);
            let H_i: BigInt = Paillier::encrypt_with_chosen_randomness(
                &self.secrets.ek,
                RawPlaintext::from(BigInt::mul(&self.k_i, &self.gamma_i)),
                &Randomness::from(H_i_randomness.clone()),
            )
            .into();

            let witness_H_i = PaillierMulWitness::new(
                self.k_i,
                self.nu_i.clone(),
                self.nu_i.mul(&self.gamma_i),
            );
            let statement_H_i = PaillierMulStatement {
                N: self.secrets.ek.n.clone(),
                NN: self.secrets.ek.nn.clone(),
                C: self.G_i,
                Y: self.K_i,
                X: H_i.clone(),
                ek_prover: self.secrets.ek.clone(),
                phantom: PhantomData,
            };

            let proof_H_i = PaillierMulProof::<Secp256k1, Sha256>::prove(
                &witness_H_i,
                &statement_H_i,
            );

            // delta_i proofs
            let s_j_i = BigInt::zero();
            let ciphertext_delta_i = H_i;
            let delta_i_randomness = H_i_randomness.clone();
            self.ssid.P.iter().for_each(|j| {
                if *j != self.ssid.X.i {
                    ciphertext_delta_i
                        .mul(self.D_i.get(j).unwrap_or(&BigInt::zero()))
                        .mul(
                            self.F_j
                                .get(&self.ssid.X.i)
                                .unwrap_or(&BigInt::zero()),
                        );
                    delta_i_randomness
                        .mul(&self.rho_i)
                        .mul(&s_j_i)
                        .mul(self.r_i.get(j).unwrap_or(&BigInt::zero()));
                }
            });

            let witness_delta_i = PaillierDecryptionModQWitness::new(
                Paillier::decrypt(
                    &self.secrets.dk,
                    RawCiphertext::from(ciphertext_delta_i.clone()),
                )
                .into(),
                H_i_randomness,
            );

            // l to statement
            let mut statement_delta_i: HashMap<
                u16,
                PaillierDecryptionModQStatement<Secp256k1, Sha256>,
            > = HashMap::new();

            // l to proof
            let mut proof_delta_i: HashMap<
                u16,
                PaillierDecryptionModQProof<Secp256k1, Sha256>,
            > = HashMap::new();

            self.ssid.P.iter().for_each(|l| {
                if *l != self.ssid.X.i {
                    let statement_delta_l_i = PaillierDecryptionModQStatement {
                        S: self.S.get(l).unwrap_or(&BigInt::zero()).clone(),
                        T: self.T.get(l).unwrap_or(&BigInt::zero()).clone(),
                        N_hat: self
                            .N_hats
                            .get(l)
                            .unwrap_or(&BigInt::zero())
                            .clone(),
                        N0: self.secrets.ek.n.clone(),
                        NN0: self.secrets.ek.nn.clone(),
                        C: ciphertext_delta_i.clone(),
                        x: self.delta_i.clone(),
                        ek_prover: self.secrets.ek.clone(),
                        phantom: PhantomData,
                    };

                    statement_delta_i.insert(*l, statement_delta_l_i.clone());

                    proof_delta_i.insert(
                        *l,
                        PaillierDecryptionModQProof::<Secp256k1, Sha256>::prove(
                            &witness_delta_i,
                            &statement_delta_l_i,
                        ),
                    );
                }
            });

            let body = Some(IdentifiableAbortBroadcastMessage {
                i: self.ssid.X.i,
                statements_D_j_i,
                proofs_D_j_i,
                statement_H_i,
                proof_H_i,
                statement_delta_i,
                proof_delta_i,
            });

            output.push(Msg {
                sender: self.ssid.X.i,
                receiver: None,
                body: Box::new(body),
            });
            Ok(Round4 {
                ssid: self.ssid,
                output: None,
                transcript: None,
            })
        }
    }

    pub fn is_expensive(&self) -> bool {
        false
    }
    pub fn expects_messages(i: u16, n: u16) -> Round2Messages {
        P2PMsgsStore::new(i, n)
    }
}

pub struct Round4 {
    ssid: SSID<Secp256k1>,
    output: Option<PresigningOutput<Secp256k1>>,
    transcript: Option<PresigningTranscript<Secp256k1>>,
}

impl Round4 {
    pub fn proceed(
        self,
        input: BroadcastMsgs<
            Option<IdentifiableAbortBroadcastMessage<Secp256k1>>,
        >,
    ) -> Result<
        Option<(PresigningOutput<Secp256k1>, PresigningTranscript<Secp256k1>)>,
    > {
        if self.output.is_some() {
            Ok(Some((self.output.unwrap(), self.transcript.unwrap())))
        } else {
            for msg in input.into_vec() {
                let msg = msg.unwrap();
                // si stands for sender index
                let si = msg.i;
                let mut vec_D_si_j_proof_bad_actors: Vec<usize> = vec![];
                // Check D_i_j proofs
                self.ssid.P.iter().for_each(|j| {
                    if *j != self.ssid.X.i {
                        let D_si_j_proof =
                            msg.proofs_D_j_i.get(&(self.ssid.X.i, *j)).unwrap();

                        let statement_D_si_j = msg
                            .statements_D_j_i
                            .get(&(self.ssid.X.i, *j))
                            .unwrap();

                        if PaillierAffineOpWithGroupComInRangeProof::<
                            Secp256k1,
                            Sha256,
                        >::verify(
                            D_si_j_proof, statement_D_si_j
                        )
                        .is_err()
                        {
                            vec_D_si_j_proof_bad_actors.push(*j as usize);
                        }
                    }
                });

                if !vec_D_si_j_proof_bad_actors.is_empty() {
                    let error_data = ProofVerificationErrorData {
                        proof_symbol: "D_si_j".to_string(),
                        verifying_party: self.ssid.X.i,
                    };
                    return Err(PresignError::ProofVerificationError(
                        ErrorType {
                            error_type: "mul".to_string(),
                            bad_actors: vec_D_si_j_proof_bad_actors,
                            data: bincode::serialize(&error_data).unwrap(),
                        },
                    ));
                }
                // Check H_j proofs
                let proof_H_si = msg.proof_H_i;
                let statement_H_si = msg.statement_H_i;

                if PaillierMulProof::verify(&proof_H_si, &statement_H_si)
                    .is_err()
                {
                    let error_data = ProofVerificationErrorData {
                        proof_symbol: "H_si".to_string(),
                        verifying_party: self.ssid.X.i,
                    };
                    return Err(PresignError::ProofVerificationError(
                        ErrorType {
                            error_type: "mul".to_string(),
                            bad_actors: vec![si.into()],
                            data: bincode::serialize(&error_data).unwrap(),
                        },
                    ));
                }
                // Check delta_si_proof
                let proof_delta_si =
                    msg.proof_delta_i.get(&self.ssid.X.i).unwrap();
                let statement_delta_si =
                    msg.statement_delta_i.get(&self.ssid.X.i).unwrap();

                if PaillierDecryptionModQProof::verify(
                    proof_delta_si,
                    statement_delta_si,
                )
                .is_err()
                {
                    let error_data = ProofVerificationErrorData {
                        proof_symbol: "delta_si".to_string(),
                        verifying_party: self.ssid.X.i,
                    };
                    return Err(PresignError::ProofVerificationError(
                        ErrorType {
                            error_type: "dec-q".to_string(),
                            bad_actors: vec![si.into()],
                            data: bincode::serialize(&error_data).unwrap(),
                        },
                    ));
                }
            }
            Ok(None)
        }
    }

    pub fn is_expensive(&self) -> bool {
        false
    }
    pub fn expects_messages(i: u16, n: u16) -> Round3Messages {
        BroadcastMsgsStore::new(i, n)
    }
}

type Result<T> = std::result::Result<T, PresignError>;

#[derive(Error, Debug, Clone)]
pub enum PresignError {
    #[error("Proof Verification Error")]
    ProofVerificationError(ErrorType),
}
