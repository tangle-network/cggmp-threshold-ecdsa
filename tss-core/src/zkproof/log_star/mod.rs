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

//! Knowledge of Exponent vs Paillier Encryption – Π^{log∗}
//!
//! Common input is (G, q, N0, C, X, g).
//! The Prover has secret input (x,ρ) such that
//!         x ∈ ± 2l, and C = (1 + N0)^x · ρ^N0 mod N0^2 and X = g^x    ∈ G.

use crate::security_level::{L, L_PLUS_EPSILON};
use crate::utilities::RingPedersenParams;
use crate::utilities::{
    mod_pow_with_negative, sample_relatively_prime_integer,
};
use curv::{
    arithmetic::{traits::*, Modulo},
    cryptographic_primitives::hashing::{Digest, DigestExt},
    elliptic::curves::{Curve, Point, Scalar},
    BigInt,
};
use paillier::{
    EncryptWithChosenRandomness, EncryptionKey, Paillier, Randomness,
    RawPlaintext,
};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PiLogStarError {
    Serialization,
    Validation,
    Challenge,
    Proof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiLogStarStatement<E: Curve, H: Digest + Clone> {
    pub N0: BigInt,
    pub NN0: BigInt,
    pub C: BigInt,
    pub X: Point<E>,
    // Πlog∗ states X = g^x.
    // This g is not allows the generator of secp256k1.
    // An example is 3-Round Presigning (see Figure 7, Round 3 in the paper)
    // where:
    // - x = k_i
    // - X = Delta_i
    // - Delta_i = Gamma^{k_i}
    // :- g = Gamma
    pub g: Point<E>,
    pub RPParams: RingPedersenParams,
    pub phantom: PhantomData<(E, H)>,
}

pub struct PiLogStarWitness<E: Curve, H: Digest + Clone> {
    x: BigInt,
    rho: BigInt,
    phantom: PhantomData<(E, H)>,
}

impl<E: Curve, H: Digest + Clone> PiLogStarWitness<E, H> {
    pub fn new(x: BigInt, rho: BigInt) -> Self {
        PiLogStarWitness {
            x,
            rho,
            phantom: PhantomData,
        }
    }
}

impl<E: Curve, H: Digest + Clone> PiLogStarStatement<E, H> {
    #[allow(clippy::too_many_arguments)]
    pub fn generate(
        rho: BigInt,
        g: Option<Point<E>>,
        rpparam: RingPedersenParams,
        paillier_key: EncryptionKey,
    ) -> (Self, PiLogStarWitness<E, H>) {
        // Set up exponents
        let l_exp = BigInt::pow(&BigInt::from(2), L as u32);
        // Set up moduli
        let N0 = paillier_key.clone().n;
        let NN0 = paillier_key.nn;
        let x = BigInt::sample_range(&BigInt::from(-1).mul(&l_exp), &l_exp);
        let g = g.unwrap_or(Point::<E>::generator().to_point());
        let X = &g * Scalar::from(&x);
        let C: BigInt = Paillier::encrypt_with_chosen_randomness(
            &EncryptionKey {
                n: N0.clone(),
                nn: NN0.clone(),
            },
            RawPlaintext::from(&x),
            &Randomness::from(&rho),
        )
        .into();
        (
            Self {
                N0,
                NN0,
                C,
                X,
                g,
                RPParams: rpparam,
                phantom: PhantomData,
            },
            PiLogStarWitness {
                x,
                rho,
                phantom: PhantomData,
            },
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiLogStarCommitment<E: Curve> {
    S: BigInt,
    A: BigInt,
    Y: Point<E>,
    D: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiLogStarProof<E: Curve, H: Digest + Clone> {
    z_1: BigInt,
    z_2: BigInt,
    z_3: BigInt,
    commitment: PiLogStarCommitment<E>,
    phantom: PhantomData<(E, H)>,
}

// Link to the UC non-interactive threshold ECDSA paper
impl<E: Curve, H: Digest + Clone> PiLogStarProof<E, H> {
    pub fn prove(
        witness: &PiLogStarWitness<E, H>,
        statement: &PiLogStarStatement<E, H>,
    ) -> PiLogStarProof<E, H> {
        // Step 1: Sample alpha between -2^{l+ε} and 2^{l+ε}
        let alpha_upper = BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32);
        let alpha_lower = BigInt::from(-1).mul(&alpha_upper);
        let alpha = BigInt::sample_range(&alpha_lower, &alpha_upper);

        // Step 2: mu, r, gamma
        // Sample mu between -2^L * RPParams.N and 2^L * RPParams.N
        let mu_upper = BigInt::mul(
            &statement.RPParams.N,
            &BigInt::pow(&BigInt::from(2), L as u32),
        );
        let mu_lower = BigInt::from(-1).mul(&mu_upper);
        let mu = BigInt::sample_range(&mu_lower, &mu_upper);

        // γ ← ± 2^{l+ε} · Nˆ
        let gamma_upper = BigInt::mul(
            &statement.RPParams.N,
            &BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32),
        );
        let gamma_lower = BigInt::from(-1).mul(&gamma_upper);
        let gamma = BigInt::sample_range(&gamma_lower, &gamma_upper);
        // Sample r from Z*_{N_0}
        let r = sample_relatively_prime_integer(&statement.N0.clone());

        // S = s^x t^mu mod RPParams.N
        let S = BigInt::mod_mul(
            &mod_pow_with_negative(
                &statement.RPParams.s,
                &witness.x,
                &statement.RPParams.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParams.t,
                &mu,
                &statement.RPParams.N,
            ),
            &statement.RPParams.N,
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

        // Y = g^alpha
        let Y = &statement.g * Scalar::from_bigint(&alpha);
        // D = s^alpha t^gamma mod RPParams.N
        let D = BigInt::mod_mul(
            &mod_pow_with_negative(
                &statement.RPParams.s,
                &alpha,
                &statement.RPParams.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParams.t,
                &gamma,
                &statement.RPParams.N,
            ),
            &statement.RPParams.N,
        );

        let commitment = PiLogStarCommitment {
            S: S.clone(),
            A: A.clone(),
            Y: Y.clone(),
            D: D.clone(),
        };

        let e = H::new()
            .chain_bigint(&S)
            .chain_bigint(&A)
            .chain_point(&Y)
            .chain_bigint(&D)
            .result_bigint();

        // Step 5: Compute z_1, z_2, z_3
        // z_1 = alpha + ex
        let z_1 = BigInt::add(&alpha, &BigInt::mul(&e, &witness.x));
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
        proof: &PiLogStarProof<E, H>,
        statement: &PiLogStarStatement<E, H>,
    ) -> Result<(), PiLogStarError> {
        let e = H::new()
            .chain_bigint(&proof.commitment.S)
            .chain_bigint(&proof.commitment.A)
            .chain_point(&proof.commitment.Y)
            .chain_bigint(&proof.commitment.D)
            .result_bigint();

        // left_1 = (1+N_0)^{z_1}z_2^{N_0} mod N_0^2
        let left_1: BigInt = Paillier::encrypt_with_chosen_randomness(
            &EncryptionKey {
                n: statement.N0.clone(),
                nn: statement.NN0.clone(),
            },
            RawPlaintext::from(&proof.z_1),
            &Randomness::from(&proof.z_2),
        )
        .into();

        // right_1 = A * C^e
        let right_1 = BigInt::mod_mul(
            &proof.commitment.A,
            &mod_pow_with_negative(&statement.C, &e, &statement.NN0),
            &statement.NN0,
        );

        // left_2 = g^z_1
        let left_2 = &statement.g * Scalar::from_bigint(&proof.z_1);
        // right_2 = Y * X^e
        let right_2 = proof.commitment.Y.clone()
            + (statement.X.clone() * Scalar::from_bigint(&e));

        // left_3 = s^z_1 t^z_3 mod RPParams.N
        let left_3 = BigInt::mod_mul(
            &mod_pow_with_negative(
                &statement.RPParams.s,
                &proof.z_1,
                &statement.RPParams.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParams.t,
                &proof.z_3,
                &statement.RPParams.N,
            ),
            &statement.RPParams.N,
        );

        // right_3 = D * S^e mod RPParams.N
        let right_3 = BigInt::mod_mul(
            &proof.commitment.D,
            &mod_pow_with_negative(
                &proof.commitment.S,
                &e,
                &statement.RPParams.N,
            ),
            &statement.RPParams.N,
        );

        if left_1.mod_floor(&statement.NN0) != right_1
            || left_2 != right_2
            || left_3 != right_3
        {
            return Err(PiLogStarError::Proof);
        }

        // Range Check -2^{L + eps} <= z_1 <= 2^{L+eps}
        let lower_bound_check: bool = proof.z_1
            >= BigInt::from(-1)
                .mul(&BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32));

        let upper_bound_check =
            proof.z_1 <= BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32);

        if !(lower_bound_check && upper_bound_check) {
            return Err(PiLogStarError::Proof);
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
    fn test_log_star_proof() {
        let (rpparam, _) = generate_safe_h1_h2_N_tilde();
        let (paillier_key, _) =
            Paillier::keypair_with_modulus_size(BITS_PAILLIER).keys();

        let rho: BigInt = sample_relatively_prime_integer(&paillier_key.n);
        let (statement, witness) =
            PiLogStarStatement::<Secp256k1, Sha256>::generate(
                rho,
                Some(Point::<Secp256k1>::generator().to_point()),
                rpparam,
                paillier_key,
            );
        let proof =
            PiLogStarProof::<Secp256k1, Sha256>::prove(&witness, &statement);
        assert!(PiLogStarProof::<Secp256k1, Sha256>::verify(
            &proof, &statement
        )
        .is_ok());
    }
}
