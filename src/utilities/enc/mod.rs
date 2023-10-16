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

//! Paillier Encryption in Range ZK – Π^enc
//!
//! Common input is (N0, K). The Prover has secret input (k, ρ) such that
//!             k ∈ ± 2l, and K = (1 + N0)^k · ρ^N0 mod N0^2.

use super::sample_relatively_prime_integer;
use crate::utilities::{mod_pow_with_negative, L};
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
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use zk_paillier::zkproofs::IncorrectProof;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierEncryptionInRangeStatement<E: Curve, H: Digest + Clone> {
    pub N0: BigInt,
    pub NN0: BigInt,
    pub K: BigInt,
    pub s: BigInt,
    pub t: BigInt,
    pub N_hat: BigInt,
    pub phantom: PhantomData<(E, H)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierEncryptionInRangeWitness<E: Curve, H: Digest + Clone> {
    k: BigInt,
    rho: BigInt,
    phantom: PhantomData<(E, H)>,
}

impl<E: Curve, H: Digest + Clone> PaillierEncryptionInRangeWitness<E, H> {
    pub fn new(k: BigInt, rho: BigInt) -> Self {
        PaillierEncryptionInRangeWitness {
            k,
            rho,
            phantom: PhantomData,
        }
    }
}

impl<E: Curve, H: Digest + Clone> PaillierEncryptionInRangeStatement<E, H> {
    #[allow(clippy::too_many_arguments)]
    pub fn generate(
        rho: BigInt,
        s: BigInt,
        t: BigInt,
        N_hat: BigInt,
        paillier_key: EncryptionKey,
    ) -> (Self, PaillierEncryptionInRangeWitness<E, H>) {
        // Set up exponents
        let _l_exp = BigInt::pow(&BigInt::from(2), L as u32);
        // Set up moduli
        let N0 = paillier_key.clone().n;
        let NN0 = paillier_key.clone().nn;
        let k = BigInt::sample_below(Scalar::<E>::group_order());
        let K: BigInt = Paillier::encrypt_with_chosen_randomness(
            &paillier_key,
            RawPlaintext::from(&k),
            &Randomness::from(&rho),
        )
        .into();

        (
            Self {
                N0,
                NN0,
                K,
                s,
                t,
                N_hat,
                phantom: PhantomData,
            },
            PaillierEncryptionInRangeWitness {
                k,
                rho,
                phantom: PhantomData,
            },
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierEncryptionInRangeCommitment {
    S: BigInt,
    A: BigInt,
    C: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierEncryptionInRangeProof<E: Curve, H: Digest + Clone> {
    z_1: BigInt,
    z_2: BigInt,
    z_3: BigInt,
    commitment: PaillierEncryptionInRangeCommitment,
    phantom: PhantomData<(E, H)>,
}

impl<E: Curve, H: Digest + Clone> PaillierEncryptionInRangeProof<E, H> {
    #[allow(dead_code)]
    pub fn prove(
        witness: &PaillierEncryptionInRangeWitness<E, H>,
        statement: &PaillierEncryptionInRangeStatement<E, H>,
    ) -> Self {
        // Step 1: Sample alpha between -2^{L+eps} and 2^{L+eps}
        let alpha_upper = BigInt::pow(
            &BigInt::from(2),
            crate::utilities::L_PLUS_EPSILON as u32,
        );
        let alpha_lower = BigInt::from(-1).mul(&alpha_upper);
        let alpha = BigInt::sample_range(&alpha_lower, &alpha_upper);

        // Step 2: mu, r, gamma
        // Sample mu between -2^L * N_hat and 2^L * N_hat
        let mu_upper = BigInt::mul(
            &statement.N_hat,
            &BigInt::pow(&BigInt::from(2), crate::utilities::L as u32),
        );
        let mu_lower = BigInt::from(-1).mul(&mu_upper);
        let mu = BigInt::sample_range(&mu_lower, &mu_upper);

        // γ ← ± 2^{l+ε} · Nˆ
        let gamma_upper = BigInt::mul(
            &statement.N_hat,
            &BigInt::pow(
                &BigInt::from(2),
                crate::utilities::L_PLUS_EPSILON as u32,
            ),
        );
        let gamma_lower = BigInt::from(-1).mul(&gamma_upper);
        let gamma = BigInt::sample_range(&gamma_lower, &gamma_upper);
        // Sample r from Z*_{N_0}
        let r = sample_relatively_prime_integer(&statement.N0.clone());

        // Step 3: S, A, C
        // S = s^k t^mu mod N_hat
        let S = BigInt::mod_mul(
            &mod_pow_with_negative(&statement.s, &witness.k, &statement.N_hat),
            &mod_pow_with_negative(&statement.t, &mu, &statement.N_hat),
            &statement.N_hat,
        );

        // A = (1+N_0)^{alpha}r^{N_0} mod N_0^2
        let A: BigInt = Paillier::encrypt_with_chosen_randomness(
            &EncryptionKey {
                n: statement.N0.clone(),
                nn: statement.NN0.clone(),
            },
            RawPlaintext::from(&alpha),
            &Randomness::from(&r),
        )
        .into();

        // C = s^alpha * t^gamma mod N_hat
        let C = BigInt::mod_mul(
            &mod_pow_with_negative(&statement.s, &alpha, &statement.N_hat),
            &mod_pow_with_negative(&statement.t, &gamma, &statement.N_hat),
            &statement.N_hat,
        );

        let commitment = PaillierEncryptionInRangeCommitment {
            S: S.clone(),
            A: A.clone(),
            C: C.clone(),
        };

        // Step 4: Hash S, A, C
        let e = H::new()
            .chain_bigint(&S)
            .chain_bigint(&A)
            .chain_bigint(&C)
            .result_bigint();

        // Step 5: Compute z_1, z_2, z_3
        // z_1 = alpha + ek
        let z_1 = BigInt::add(&alpha, &BigInt::mul(&e, &witness.k));
        // z_2 = r * rho^e mod N_0
        let z_2 = BigInt::mod_mul(
            &r,
            &mod_pow_with_negative(&witness.rho, &e, &statement.N0),
            &statement.N0,
        );
        // z_3 = gamma + e*mu
        let z_3 = BigInt::add(&gamma, &BigInt::mul(&e, &mu));

        Self {
            z_1,
            z_2,
            z_3,
            commitment,
            phantom: PhantomData,
        }
    }

    #[allow(dead_code)]
    pub fn verify(
        proof: &PaillierEncryptionInRangeProof<E, H>,
        statement: &PaillierEncryptionInRangeStatement<E, H>,
    ) -> Result<(), IncorrectProof> {
        let e = H::new()
            .chain_bigint(&proof.commitment.S)
            .chain_bigint(&proof.commitment.A)
            .chain_bigint(&proof.commitment.C)
            .result_bigint();

        // Equality Checks
        let NN0 = statement.NN0.clone();
        // left_1 = (1+N_0)^{z_1}z_2^{N_0} mod N_0^2
        let left_1: BigInt = Paillier::encrypt_with_chosen_randomness(
            &EncryptionKey {
                n: statement.N0.clone(),
                nn: NN0.clone(),
            },
            RawPlaintext::from(&proof.z_1),
            &Randomness::from(&proof.z_2),
        )
        .into();
        // right_1 = A * K^e mod N_0^2
        let right_1 = BigInt::mod_mul(
            &proof.commitment.A,
            &mod_pow_with_negative(&statement.K, &e, &NN0),
            &NN0,
        );

        // left_2 = s^z_1 t^z_3 mod N_hat
        let left_2 = BigInt::mod_mul(
            &mod_pow_with_negative(&statement.s, &proof.z_1, &statement.N_hat),
            &mod_pow_with_negative(&statement.t, &proof.z_3, &statement.N_hat),
            &statement.N_hat,
        );
        // right_2 = C * S^e mod N_hat
        let right_2 = BigInt::mod_mul(
            &proof.commitment.C,
            &mod_pow_with_negative(&proof.commitment.S, &e, &statement.N_hat),
            &statement.N_hat,
        );

        if left_1.mod_floor(&NN0) != right_1 || left_2 != right_2 {
            return Err(IncorrectProof);
        }

        // Range Check -2^{L + eps} <= z_1 <= 2^{L+eps}
        let lower_bound_check: bool = proof.z_1
            >= BigInt::from(-1).mul(&BigInt::pow(
                &BigInt::from(2),
                crate::utilities::L_PLUS_EPSILON as u32,
            ));

        let upper_bound_check = proof.z_1
            <= BigInt::pow(
                &BigInt::from(2),
                crate::utilities::L_PLUS_EPSILON as u32,
            );

        if !(lower_bound_check && upper_bound_check) {
            return Err(IncorrectProof);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mpc_ecdsa::utilities::mta::range_proofs::SampleFromMultiplicativeGroup,
        utilities::BITS_PAILLIER,
    };
    use curv::elliptic::curves::secp256_k1::Secp256k1;
    use fs_dkr::ring_pedersen_proof::RingPedersenStatement;
    use paillier::{KeyGeneration, Paillier};
    use sha2::Sha256;

    #[test]
    fn test_paillier_encryption_in_range_proof() {
        let (ring_pedersen_statement, _witness) =
            RingPedersenStatement::<Secp256k1, Sha256>::generate();
        let (paillier_key, _) =
            Paillier::keypair_with_modulus_size(BITS_PAILLIER).keys();

        let rho: BigInt = BigInt::from_paillier_key(&paillier_key);
        let (statement, witness) =
            PaillierEncryptionInRangeStatement::<Secp256k1, Sha256>::generate(
                rho,
                ring_pedersen_statement.S,
                ring_pedersen_statement.T,
                ring_pedersen_statement.N,
                paillier_key,
            );
        let proof = PaillierEncryptionInRangeProof::<Secp256k1, Sha256>::prove(
            &witness, &statement,
        );
        assert!(PaillierEncryptionInRangeProof::<Secp256k1, Sha256>::verify(
            &proof, &statement,
        )
        .is_ok());
    }
}
