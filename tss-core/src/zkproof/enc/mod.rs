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

use crate::security_level::{L, L_PLUS_EPSILON};
use crate::utilities::mod_pow_with_negative;
use crate::utilities::sample_relatively_prime_integer;
use crate::utilities::RingPedersenParams;
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiEncStatement<E: Curve, H: Digest + Clone> {
    pub N0: BigInt,
    pub NN0: BigInt,
    pub K: BigInt,
    pub RPParam: RingPedersenParams,
    pub phantom: PhantomData<(E, H)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiEncWitness<E: Curve, H: Digest + Clone> {
    k: BigInt,
    rho: BigInt,
    phantom: PhantomData<(E, H)>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PiEncError {
    Serialization,
    Validation,
    Challenge,
    Proof,
}

impl<E: Curve, H: Digest + Clone> PiEncWitness<E, H> {
    pub fn new(k: BigInt, rho: BigInt) -> Self {
        PiEncWitness {
            k,
            rho,
            phantom: PhantomData,
        }
    }
}

impl<E: Curve, H: Digest + Clone> PiEncStatement<E, H> {
    #[allow(clippy::too_many_arguments)]
    pub fn generate(
        rho: BigInt,
        rpparam: RingPedersenParams,
        paillier_key: EncryptionKey,
    ) -> (Self, PiEncWitness<E, H>) {
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
                RPParam: rpparam,
                phantom: PhantomData,
            },
            PiEncWitness {
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
pub struct PiEncProof<E: Curve, H: Digest + Clone> {
    z_1: BigInt,
    z_2: BigInt,
    z_3: BigInt,
    commitment: PaillierEncryptionInRangeCommitment,
    phantom: PhantomData<(E, H)>,
}

impl<E: Curve, H: Digest + Clone> PiEncProof<E, H> {
    pub fn prove(
        witness: &PiEncWitness<E, H>,
        statement: &PiEncStatement<E, H>,
    ) -> Self {
        // Step 1: Sample alpha between -2^{L+eps} and 2^{L+eps}
        let alpha_upper = BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32);
        let alpha_lower = BigInt::from(-1).mul(&alpha_upper);
        let alpha = BigInt::sample_range(&alpha_lower, &alpha_upper);

        // Step 2: mu, r, gamma
        // Sample mu between -2^L * N_hat and 2^L * N_hat
        let mu_upper = BigInt::mul(
            &statement.RPParam.N,
            &BigInt::pow(&BigInt::from(2), L as u32),
        );
        let mu_lower = BigInt::from(-1).mul(&mu_upper);
        let mu = BigInt::sample_range(&mu_lower, &mu_upper);

        // γ ← ± 2^{l+ε} · Nˆ
        let gamma_upper = BigInt::mul(
            &statement.RPParam.N,
            &BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32),
        );
        let gamma_lower = BigInt::from(-1).mul(&gamma_upper);
        let gamma = BigInt::sample_range(&gamma_lower, &gamma_upper);
        // Sample r from Z*_{N_0}
        let r = sample_relatively_prime_integer(&statement.N0.clone());

        // Step 3: S, A, C
        // S = s^k t^mu mod N_hat
        let S = BigInt::mod_mul(
            &mod_pow_with_negative(
                &statement.RPParam.s,
                &witness.k,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &mu,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
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
            &mod_pow_with_negative(
                &statement.RPParam.s,
                &alpha,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &gamma,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
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

    pub fn verify(
        proof: &PiEncProof<E, H>,
        statement: &PiEncStatement<E, H>,
    ) -> Result<(), PiEncError> {
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
            &mod_pow_with_negative(
                &statement.RPParam.s,
                &proof.z_1,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &proof.z_3,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        // right_2 = C * S^e mod N_hat
        let right_2 = BigInt::mod_mul(
            &proof.commitment.C,
            &mod_pow_with_negative(
                &proof.commitment.S,
                &e,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );

        if left_1.mod_floor(&NN0) != right_1 || left_2 != right_2 {
            return Err(PiEncError::Proof);
        }

        // Range Check -2^{L + eps} <= z_1 <= 2^{L+eps}
        let lower_bound_check: bool = proof.z_1
            >= BigInt::from(-1)
                .mul(&BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32));

        let upper_bound_check =
            proof.z_1 <= BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32);

        if !(lower_bound_check && upper_bound_check) {
            return Err(PiEncError::Proof);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utilities::generate_safe_h1_h2_N_tilde;
    use curv::elliptic::curves::secp256_k1::Secp256k1;
    use paillier::{KeyGeneration, Paillier};
    use sha2::Sha256;

    #[test]
    fn test_paillier_encryption_in_range_proof() {
        let (auxRPParam, _) = generate_safe_h1_h2_N_tilde();
        let (paillier_key, _) = Paillier::keypair_with_modulus_size(
            crate::security_level::BITS_PAILLIER,
        )
        .keys();

        // sample the prover secret inputs
        let rho: BigInt = sample_relatively_prime_integer(&paillier_key.n);
        let (statement, witness) =
            PiEncStatement::<Secp256k1, Sha256>::generate(
                rho,
                auxRPParam,
                paillier_key,
            );
        let proof =
            PiEncProof::<Secp256k1, Sha256>::prove(&witness, &statement);
        assert!(PiEncProof::<Secp256k1, Sha256>::verify(&proof, &statement,)
            .is_ok());
    }
}
