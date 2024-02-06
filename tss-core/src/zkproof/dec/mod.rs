#![allow(non_snake_case)]
/*
    CGGMP Threshold ECDSA

    Copyright 2022 by Webb Technologies

    This file is part of CGGMP Threshold ECDSA library
    (https://github.com/webb-tools/cggmp-threshold-ecdsa)

    CGGMP Threshold ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

use crate::security_level::{L, L_PLUS_EPSILON};
use crate::utilities::RingPedersenParams;
use crate::utilities::{
    fixed_array, mod_pow_with_negative, sample_relatively_prime_integer,
};
use curv::{
    arithmetic::{traits::*, Modulo},
    cryptographic_primitives::hashing::{Digest, DigestExt},
    elliptic::curves::{Curve, Scalar},
    BigInt,
};
use paillier::{
    EncryptWithChosenRandomness, EncryptionKey, Paillier, Randomness,
    RawPlaintext,
};
use rand::Rng;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PiDecError {
    Proof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiDecStatement<E: Curve, H: Digest + Clone> {
    pub RPParams: RingPedersenParams,
    pub N0: BigInt,
    pub NN0: BigInt,
    pub C: BigInt,
    pub x: BigInt,
    pub ek_prover: EncryptionKey,
    pub phantom: PhantomData<(E, H)>,
}

pub struct PiDecWitness<E: Curve, H: Digest + Clone> {
    y: BigInt,
    rho: BigInt,
    phantom: PhantomData<(E, H)>,
}

impl<E: Curve, H: Digest + Clone> PiDecWitness<E, H> {
    pub fn new(y: BigInt, rho: BigInt) -> Self {
        PiDecWitness {
            y,
            rho,
            phantom: PhantomData,
        }
    }
}

impl<E: Curve, H: Digest + Clone> PiDecStatement<E, H> {
    #[allow(clippy::too_many_arguments)]
    pub fn generate(
        rpparams: RingPedersenParams,
        rho: BigInt,
        prover: EncryptionKey,
    ) -> (Self, PiDecWitness<E, H>) {
        let ek_prover = prover.clone();
        // y <- Z_N
        let y = BigInt::sample_below(&prover.n);
        // C = (1 + N0)^y * rho^N0 mod N0^2
        let C = {
            let C_ciphertext = Paillier::encrypt_with_chosen_randomness(
                &ek_prover,
                RawPlaintext::from(y.clone()),
                &Randomness::from(rho.clone()),
            );
            let C: BigInt = C_ciphertext.into();
            C
        };
        let x = BigInt::mod_floor(&y, Scalar::<E>::group_order());
        (
            Self {
                RPParams: rpparams,
                N0: prover.n,
                NN0: prover.nn,
                C,
                x,
                ek_prover,
                phantom: PhantomData,
            },
            PiDecWitness {
                y,
                rho,
                phantom: PhantomData,
            },
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiDecCommitment {
    A: BigInt,
    gamma: BigInt,
    big_S: BigInt,
    big_T: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiDecProof<E: Curve, H: Digest + Clone> {
    z1: BigInt,
    z2: BigInt,
    w: BigInt,
    commitment: PiDecCommitment,
    phantom: PhantomData<(E, H)>,
}

// Link to the UC non-interactive threshold ECDSA paper
impl<E: Curve, H: Digest + Clone> PiDecProof<E, H> {
    pub fn prove(
        witness: &PiDecWitness<E, H>,
        statement: &PiDecStatement<E, H>,
    ) -> PiDecProof<E, H> {
        // Set up exponents
        let l_exp = BigInt::pow(&BigInt::from(2), L as u32);
        let lplus_exp = BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32);
        // α ← ± 2^{l+ε}
        let alpha =
            BigInt::sample_range(&BigInt::from(-1).mul(&lplus_exp), &lplus_exp);
        // mu ← ± 2l · Nˆ
        let mu = BigInt::sample_range(
            &BigInt::from(-1).mul(&l_exp).mul(&statement.RPParams.N),
            &l_exp.mul(&statement.RPParams.N),
        );
        // nu ← 2^{l+ε} · Nˆ
        let nu = BigInt::sample_range(
            &BigInt::from(-1).mul(&lplus_exp).mul(&statement.RPParams.N),
            &lplus_exp.mul(&statement.RPParams.N),
        );
        // r <- Z*_N
        let r = sample_relatively_prime_integer(&statement.N0);
        // big_S = s^y * t^μ mod Nˆ
        let big_S = {
            let s = BigInt::mod_pow(
                &statement.RPParams.s,
                &witness.y,
                &statement.RPParams.N,
            );
            let t = mod_pow_with_negative(
                &statement.RPParams.t,
                &mu,
                &statement.RPParams.N,
            );
            BigInt::mod_mul(&s, &t, &statement.RPParams.N)
        };
        // big_T = s^α & t^ν mod Nˆ
        let big_T = {
            let s = mod_pow_with_negative(
                &statement.RPParams.s,
                &alpha,
                &statement.RPParams.N,
            );
            let t = mod_pow_with_negative(
                &statement.RPParams.t,
                &nu,
                &statement.RPParams.N,
            );
            BigInt::mod_mul(&s, &t, &statement.RPParams.N)
        };
        // A = (1 + N0)^α * r^N0 mod N0^2
        let A = {
            let A_ciphertext = Paillier::encrypt_with_chosen_randomness(
                &statement.ek_prover,
                RawPlaintext::from(alpha.clone()),
                &Randomness::from(r.clone()),
            );
            let A: BigInt = A_ciphertext.into();
            A.mod_floor(&statement.NN0)
        };
        // gamma = alpha mod q
        let gamma = BigInt::mod_floor(&alpha, Scalar::<E>::group_order());
        // Generate NIZK challenge
        let mut e = H::new()
            .chain_bigint(&A)
            .chain_bigint(&gamma)
            .chain_bigint(&big_S)
            .chain_bigint(&big_T)
            .result_bigint();
        let mut rng: ChaChaRng =
            ChaChaRng::from_seed(fixed_array::<32>(e.to_bytes()).unwrap());
        let val = rng.gen_range(0..2);
        e = BigInt::from(val)
            .mul(&BigInt::from(-2))
            .add(&BigInt::one())
            .mul(&e);
        let commitment: PiDecCommitment = PiDecCommitment {
            A,
            gamma,
            big_S,
            big_T,
        };
        // z1 = α + e · y
        let z1 = BigInt::add(&alpha, &BigInt::mul(&e, &witness.y));
        // z2 = ν + e · μ
        let z2 = BigInt::add(&nu, &BigInt::mul(&e, &mu));
        // w = r · rho^e mod N0
        let w = {
            let rho = mod_pow_with_negative(&witness.rho, &e, &statement.N0);
            BigInt::mod_mul(&r, &rho, &statement.N0)
        };
        // Return the proof
        PiDecProof {
            z1,
            z2,
            w,
            commitment,
            phantom: PhantomData,
        }
    }

    pub fn verify(
        proof: &PiDecProof<E, H>,
        statement: &PiDecStatement<E, H>,
    ) -> Result<(), PiDecError> {
        // Compute the challenge
        let mut e = H::new()
            .chain_bigint(&proof.commitment.A)
            .chain_bigint(&proof.commitment.gamma)
            .chain_bigint(&proof.commitment.big_S)
            .chain_bigint(&proof.commitment.big_T)
            .result_bigint();
        let mut rng: ChaChaRng =
            ChaChaRng::from_seed(fixed_array::<32>(e.to_bytes()).unwrap());
        let val = rng.gen_range(0..2);
        e = BigInt::from(val)
            .mul(&BigInt::from(-2))
            .add(&BigInt::one())
            .mul(&e);
        /*
            FIRST EQUALITY CHECK
            (1 + N0)^z1 · w^N0 = A · C^e mod N0^2 === Enc(z1,w) = A · C^e mod N0^2
        */
        // Compute the left hand side
        let left_1 = {
            let left_1_ciphertext = Paillier::encrypt_with_chosen_randomness(
                &statement.ek_prover,
                RawPlaintext::from(proof.z1.clone()),
                &Randomness::from(proof.w.clone()),
            );
            let left_1: BigInt = left_1_ciphertext.into();
            left_1.mod_floor(&statement.NN0)
        };
        // Compute the right hand side
        let right_1 = {
            let C = mod_pow_with_negative(&statement.C, &e, &statement.NN0);
            BigInt::mod_mul(&proof.commitment.A, &C, &statement.NN0)
        };
        // Check the equality
        if left_1 != right_1 {
            return Err(PiDecError::Proof);
        }
        /*
            SECOND EQUALITY CHECK
            z1 = γ + e * x mod q
        */
        // Compute the left hand side
        let left_2 = proof.z1.clone().mod_floor(Scalar::<E>::group_order());
        // Compute the right hand side
        let right_2 = BigInt::mod_add(
            &proof.commitment.gamma,
            &BigInt::mod_mul(&e, &statement.x, Scalar::<E>::group_order()),
            Scalar::<E>::group_order(),
        );
        // Check the equality
        if left_2 != right_2 {
            return Err(PiDecError::Proof);
        }
        /*
            THIRD EQUALITY CHECK
            s^z1 · t^z2 = T · S^e mod Nˆ
        */
        // Compute the left hand side
        let left_3 = {
            let s = mod_pow_with_negative(
                &statement.RPParams.s,
                &proof.z1,
                &statement.RPParams.N,
            );
            let t = mod_pow_with_negative(
                &statement.RPParams.t,
                &proof.z2,
                &statement.RPParams.N,
            );
            BigInt::mod_mul(&s, &t, &statement.RPParams.N)
        };
        // Compute the right hand side
        let right_3 = {
            let temp = mod_pow_with_negative(
                &proof.commitment.big_S,
                &e,
                &statement.RPParams.N,
            );
            BigInt::mod_mul(
                &proof.commitment.big_T,
                &temp,
                &statement.RPParams.N,
            )
        };
        // Check the equality
        if left_3 != right_3 {
            return Err(PiDecError::Proof);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_level::BITS_PAILLIER;
    use crate::utilities::generate_safe_h1_h2_N_tilde;
    use curv::elliptic::curves::secp256_k1::Secp256k1;
    use paillier::{KeyGeneration, Paillier};
    use sha2::Sha256;

    #[test]
    fn test_paillier_decryption_modulo_q() {
        let (rpparam, _) = generate_safe_h1_h2_N_tilde();
        let (ek_prover, _) =
            Paillier::keypair_with_modulus_size(BITS_PAILLIER).keys();
        let rho: BigInt = sample_relatively_prime_integer(&ek_prover.n);
        let (statement, witness) =
            PiDecStatement::<Secp256k1, Sha256>::generate(
                rpparam, rho, ek_prover,
            );
        let proof =
            PiDecProof::<Secp256k1, Sha256>::prove(&witness, &statement);
        assert!(
            PiDecProof::<Secp256k1, Sha256>::verify(&proof, &statement).is_ok()
        );
    }
}
