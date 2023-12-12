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
use paillier::EncryptionKey;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PiMulStarError {
    Proof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiMulStarStatement<E: Curve, H: Digest + Clone> {
    pub N0: BigInt,
    pub NN0: BigInt,
    pub C: BigInt,
    pub D: BigInt,
    pub X: Point<E>,
    pub RPParams: RingPedersenParams,
    pub phantom: PhantomData<(E, H)>,
}

pub struct PiMulStarWitness<E: Curve, H: Digest + Clone> {
    x: BigInt,
    rho: BigInt,
    phantom: PhantomData<(E, H)>,
}

impl<E: Curve, H: Digest + Clone> PiMulStarWitness<E, H> {
    pub fn new(x: BigInt, rho: BigInt) -> Self {
        PiMulStarWitness {
            x,
            rho,
            phantom: PhantomData,
        }
    }
}

impl<E: Curve, H: Digest + Clone> PiMulStarStatement<E, H> {
    #[allow(clippy::too_many_arguments)]
    pub fn generate(
        rho: BigInt,
        _C: BigInt,
        rpparam: RingPedersenParams,
        paillier_key: EncryptionKey,
    ) -> (Self, PiMulStarWitness<E, H>) {
        // Set up exponents
        let l_exp = BigInt::pow(&BigInt::from(2), L as u32);
        // Set up moduli
        let N0 = paillier_key.clone().n;
        let NN0 = paillier_key.nn;
        let x = BigInt::sample_range(&BigInt::from(-1).mul(&l_exp), &l_exp);
        let X = Point::<E>::generator().as_point() * Scalar::from(&x);
        let C: BigInt = BigInt::zero();
        // D  = C^x * rho^(N_0) mod N_0^2
        let D = BigInt::mod_mul(
            &mod_pow_with_negative(&C, &x, &NN0),
            &BigInt::mod_pow(&rho, &N0, &NN0),
            &NN0,
        );
        (
            Self {
                N0,
                NN0,
                C,
                D,
                X,
                RPParams: rpparam,
                phantom: PhantomData,
            },
            PiMulStarWitness {
                x,
                rho,
                phantom: PhantomData,
            },
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiMulStarCommitment<E: Curve> {
    A: BigInt,
    B_x: Point<E>,
    E: BigInt,
    S: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiMulStarProof<E: Curve, H: Digest + Clone> {
    z_1: BigInt,
    z_2: BigInt,
    w: BigInt,
    commitment: PiMulStarCommitment<E>,
    phantom: PhantomData<(E, H)>,
}

// Link to the UC non-interactive threshold ECDSA paper
impl<E: Curve, H: Digest + Clone> PiMulStarProof<E, H> {
    pub fn prove(
        witness: &PiMulStarWitness<E, H>,
        statement: &PiMulStarStatement<E, H>,
    ) -> PiMulStarProof<E, H> {
        // Step 1: Sample alpha between -2^{l+ε} and 2^{l+ε}
        let alpha_upper = BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32);
        let alpha_lower = BigInt::from(-1).mul(&alpha_upper);
        let alpha = BigInt::sample_range(&alpha_lower, &alpha_upper);

        // Step 2: m, r, r_y gamma
        // Sample mu between -2^L * RPParams.N and 2^L * RPParams.N
        let m_upper = BigInt::mul(
            &statement.RPParams.N,
            &BigInt::pow(&BigInt::from(2), L as u32),
        );
        let m_lower = BigInt::from(-1).mul(&m_upper);
        let m = BigInt::sample_range(&m_lower, &m_upper);

        // γ ← ± 2^{l+ε} · Nˆ
        let gamma_upper = BigInt::mul(
            &statement.RPParams.N,
            &BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32),
        );
        let gamma_lower = BigInt::from(-1).mul(&gamma_upper);
        let gamma = BigInt::sample_range(&gamma_lower, &gamma_upper);
        // Sample r from Z*_{N_0}
        let r = sample_relatively_prime_integer(&statement.N0.clone());

        // A = C^alpha * r^N_0
        let A = BigInt::mod_mul(
            &mod_pow_with_negative(&statement.C, &alpha, &statement.NN0),
            &BigInt::mod_pow(&r, &statement.N0, &statement.NN0),
            &statement.NN0,
        );

        // B_x = g^alpha
        let B_x: Point<E> =
            Point::<E>::generator().as_point() * Scalar::from_bigint(&alpha);

        // E = s^alpha t^gamma mod RPParams.N
        let E = BigInt::mod_mul(
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

        // S = s^x t^m mod RPParams.N
        let S = BigInt::mod_mul(
            &mod_pow_with_negative(
                &statement.RPParams.s,
                &witness.x,
                &statement.RPParams.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParams.t,
                &m,
                &statement.RPParams.N,
            ),
            &statement.RPParams.N,
        );

        let e = H::new()
            .chain_bigint(&A)
            .chain_point(&B_x)
            .chain_bigint(&E)
            .chain_bigint(&S)
            .result_bigint();

        // Step 5: Compute z_1, z_2, z_3
        // z_1 = alpha + ex
        let z_1 = BigInt::add(&alpha, &BigInt::mul(&e, &witness.x));
        // z_2 = gamma + e*m
        let z_2 = BigInt::add(&gamma, &BigInt::mul(&e, &m));
        // w = r * rho^e mod N_0
        let w = BigInt::mod_mul(
            &r,
            &mod_pow_with_negative(&witness.rho, &e, &statement.N0),
            &statement.N0,
        );
        let commitment = PiMulStarCommitment { A, B_x, E, S };
        Self {
            z_1,
            z_2,
            w,
            commitment,
            phantom: PhantomData,
        }
    }

    pub fn verify(
        proof: &PiMulStarProof<E, H>,
        statement: &PiMulStarStatement<E, H>,
    ) -> Result<(), PiMulStarError> {
        let e = H::new()
            .chain_bigint(&proof.commitment.A)
            .chain_point(&proof.commitment.B_x)
            .chain_bigint(&proof.commitment.E)
            .chain_bigint(&proof.commitment.S)
            .result_bigint();

        // left_1 = (C)^{z_1}w^{N_0} mod N_0^2
        let left_1 = BigInt::mod_mul(
            &mod_pow_with_negative(&statement.C, &proof.z_1, &statement.N0),
            &BigInt::mod_pow(&proof.w, &statement.N0, &statement.NN0),
            &statement.NN0,
        );

        // right_1 = A * D^e
        let right_1 = BigInt::mod_mul(
            &proof.commitment.A,
            &mod_pow_with_negative(&statement.D, &e, &statement.NN0),
            &statement.NN0,
        );

        // left_2 = g^z_1
        let left_2 = Point::<E>::generator().as_point()
            * Scalar::from_bigint(&proof.z_1);
        // right_2 = B_x * X^e
        let right_2 = proof.commitment.B_x.clone()
            + (statement.X.clone() * Scalar::from_bigint(&e));

        // left_3 = s^z_1 t^z_2 mod RPParams.N
        let left_3 = BigInt::mod_mul(
            &mod_pow_with_negative(
                &statement.RPParams.s,
                &proof.z_1,
                &statement.RPParams.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParams.t,
                &proof.z_2,
                &statement.RPParams.N,
            ),
            &statement.RPParams.N,
        );

        // right_3 = E * S^e mod RPParams.N
        let right_3 = BigInt::mod_mul(
            &proof.commitment.E,
            &mod_pow_with_negative(
                &proof.commitment.S,
                &e,
                &statement.RPParams.N,
            ),
            &statement.RPParams.N,
        );

        if left_1 != right_1 || left_2 != right_2 || left_3 != right_3 {
            return Err(PiMulStarError::Proof);
        }

        // Range Check -2^{L + eps} <= z_1 <= 2^{L+eps}
        let lower_bound_check: bool = proof.z_1
            >= BigInt::from(-1)
                .mul(&BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32));

        let upper_bound_check =
            proof.z_1 <= BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32);

        if !(lower_bound_check && upper_bound_check) {
            return Err(PiMulStarError::Proof);
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
    use paillier::{Encrypt, KeyGeneration, Paillier, RawPlaintext};
    use sha2::Sha256;

    #[test]
    fn test_mul_star_proof() {
        let (rpparam, _) = generate_safe_h1_h2_N_tilde();
        let (paillier_key, _) =
            Paillier::keypair_with_modulus_size(BITS_PAILLIER).keys();

        let rho: BigInt = sample_relatively_prime_integer(&paillier_key.n);

        let C: BigInt = Paillier::encrypt(
            &paillier_key,
            RawPlaintext::from(BigInt::from(123)),
        )
        .into();
        let (statement, witness) =
            PiMulStarStatement::<Secp256k1, Sha256>::generate(
                rho,
                C,
                rpparam,
                paillier_key,
            );
        let proof =
            PiMulStarProof::<Secp256k1, Sha256>::prove(&witness, &statement);
        assert!(PiMulStarProof::<Secp256k1, Sha256>::verify(
            &proof, &statement
        )
        .is_ok());
    }
}
