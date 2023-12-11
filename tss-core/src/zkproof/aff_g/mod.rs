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

//! Paillier Affine Operation with Paillier Commitment ZK-Proof – Π^{aff-p}

//! For parameters (G, g, N0, N1), consisting of element g and in group G and
//! Paillier public keys N0, N1, verify the ciphertext C \in Z∗_{N0^2} was
//! obtained as an affine-like transformation on C0 such that the multiplicative
//! coefficient (i.e. ε) is equal to the exponent of X ∈ G in the range I, and
//! the additive coefficient (i.e. δ) is equal to the plaintext-value of Y ∈
//! Z_N1 and resides in the the range J.

//! Setup: Auxiliary Paillier Modulus Nˆ and Ring-Pedersen parameters s, t ∈
//! Z∗_{Nˆ}.
//!
//! Inputs: Common input is (G,g,N0,N1,C,D,Y,X) where q = |G| and g is a
//! generator of G. The Prover has secret input (x,y,ρ,ρy) such that
//!         x ∈ ± 2l, y ∈ ± 2l′, g^{x} = X, (1 + N1)^{y} · ρ^{N1} = Y mod N^2,
//! and
//!             D = C^{x} · (1+N0)^{y} · ρ^{N0} mod N0^{2}.

use crate::security_level::{L, L_PLUS_EPSILON, L_PRIME, L_PRIME_PLUS_EPSILON};
use crate::utilities::fixed_array;
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
use rand::Rng;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiAffGStatement<E: Curve, H: Digest + Clone> {
    pub RPParam: RingPedersenParams,
    pub N0: BigInt,
    pub N1: BigInt,
    pub NN0: BigInt,
    pub NN1: BigInt,
    pub C: BigInt,
    pub D: BigInt,
    pub Y: BigInt,
    pub X: Point<E>,
    pub ek_prover: EncryptionKey,
    pub ek_verifier: EncryptionKey,
    pub phantom: PhantomData<(E, H)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PiAffGError {
    Serialization,
    Validation,
    Challenge,
    Proof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiAffGWitness<E: Curve, H: Digest + Clone> {
    x: BigInt,
    y: BigInt,
    rho: BigInt,
    rho_y: BigInt,
    phantom: PhantomData<(E, H)>,
}

impl<E: Curve, H: Digest + Clone> PiAffGWitness<E, H> {
    pub fn new(x: BigInt, y: BigInt, rho: BigInt, rho_y: BigInt) -> Self {
        PiAffGWitness {
            x,
            y,
            rho,
            rho_y,
            phantom: PhantomData,
        }
    }
}

impl<E: Curve, H: Digest + Clone> PiAffGStatement<E, H> {
    #[allow(clippy::too_many_arguments)]
    pub fn generate(
        rpparam: RingPedersenParams,
        rho: BigInt,
        rho_y: BigInt,
        prover: EncryptionKey,
        verifier: EncryptionKey,
        C: BigInt,
    ) -> (Self, PiAffGWitness<E, H>) {
        // Set up exponents
        let l_exp = BigInt::pow(&BigInt::from(2), L as u32);
        let lprime_exp = BigInt::pow(&BigInt::from(2), L_PRIME as u32);
        // Set up moduli
        let N0 = verifier.clone().n;
        let NN0 = verifier.clone().nn;
        let N1 = prover.clone().n;
        let NN1 = prover.clone().nn;
        let ek_verifier = verifier;
        let ek_prover = prover;

        let x = BigInt::sample_range(&BigInt::from(-1).mul(&l_exp), &l_exp);
        let y = BigInt::sample_range(
            &BigInt::from(-1).mul(&lprime_exp),
            &lprime_exp,
        );

        let X = Point::<E>::generator().as_point() * Scalar::from(&x);
        // Y = (1 + N1)^{y} · ρ_y^{N1}
        let Y = Paillier::encrypt_with_chosen_randomness(
            &ek_prover,
            RawPlaintext::from(&y),
            &Randomness::from(&rho_y),
        );
        // (1 + N0)^y mod N0^2
        let D = {
            let D_temp = Paillier::encrypt_with_chosen_randomness(
                &ek_verifier,
                RawPlaintext::from(&y),
                &Randomness::from(&rho),
            );
            BigInt::mod_mul(
                &mod_pow_with_negative(&C, &x, &NN0),
                &D_temp.into(),
                &NN0,
            )
        };

        (
            Self {
                RPParam: rpparam,
                N0,
                N1,
                NN0,
                NN1,
                C,
                D,
                Y: Y.clone().into(),
                X,
                ek_prover,
                ek_verifier,
                phantom: PhantomData,
            },
            PiAffGWitness {
                x,
                y,
                rho,
                rho_y,
                phantom: PhantomData,
            },
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiAffGCommitment<E: Curve> {
    A: BigInt,
    B_x: Point<E>,
    B_y: BigInt,
    E: BigInt,
    F: BigInt,
    big_S: BigInt,
    big_T: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiAffGProof<E: Curve, H: Digest + Clone> {
    z1: BigInt,
    z2: BigInt,
    z3: BigInt,
    z4: BigInt,
    w: BigInt,
    wy: BigInt,
    commitment: PiAffGCommitment<E>,
    phantom: PhantomData<(E, H)>,
}

// Link to the UC non-interactive threshold ECDSA paper
impl<E: Curve, H: Digest + Clone> PiAffGProof<E, H> {
    pub fn prove(
        witness: &PiAffGWitness<E, H>,
        statement: &PiAffGStatement<E, H>,
    ) -> PiAffGProof<E, H> {
        // Set up exponents
        let l_exp = BigInt::pow(&BigInt::from(2), L as u32);
        let lplus_exp = BigInt::pow(&BigInt::from(2), L_PLUS_EPSILON as u32);
        let lprimeplus_exp =
            BigInt::pow(&BigInt::from(2), L_PRIME_PLUS_EPSILON as u32);

        // α ← ± 2^{l+ε}
        let alpha =
            BigInt::sample_range(&BigInt::from(-1).mul(&lplus_exp), &lplus_exp);
        // β ← ± 2^{l'+ε}
        let beta = BigInt::sample_range(
            &BigInt::from(-1).mul(&lprimeplus_exp),
            &lprimeplus_exp,
        );
        // Sample r, ry as unit values from Z_N0, Z_N1
        let r = sample_relatively_prime_integer(&statement.N0);
        let ry = sample_relatively_prime_integer(&statement.N1);
        // γ ← ± 2^{l+ε} · Nˆ
        let gamma = BigInt::sample_range(
            &BigInt::from(-1).mul(&lplus_exp).mul(&statement.RPParam.N),
            &lplus_exp.mul(&statement.RPParam.N),
        );
        // m ← ± 2l · Nˆ
        let m = BigInt::sample_range(
            &BigInt::from(-1).mul(&l_exp).mul(&statement.RPParam.N),
            &l_exp.mul(&statement.RPParam.N),
        );
        // δ ← ± 2^{l+ε} · Nˆ
        let delta = BigInt::sample_range(
            &BigInt::from(-1).mul(&lplus_exp).mul(&statement.RPParam.N),
            &lplus_exp.mul(&statement.RPParam.N),
        );
        // mu ← ± 2l · Nˆ
        let mu = BigInt::sample_range(
            &BigInt::from(-1).mul(&l_exp).mul(&statement.RPParam.N),
            &l_exp.mul(&statement.RPParam.N),
        );
        // A = C^α · (1 + N0)^β · r^N0 mod N0^2
        let A = {
            let A_temp = Paillier::encrypt_with_chosen_randomness(
                &statement.ek_verifier,
                RawPlaintext::from(&beta),
                &Randomness::from(&r),
            );
            BigInt::mod_mul(
                &mod_pow_with_negative(&statement.C, &alpha, &statement.NN0),
                &A_temp.into(),
                &statement.NN0,
            )
        };

        let B_x: Point<E> =
            Point::<E>::generator().as_point() * Scalar::from_bigint(&alpha);
        // By = (1 + N1)^β · ry^N1 mod N1^2
        let B_y = Paillier::encrypt_with_chosen_randomness(
            &statement.ek_prover,
            RawPlaintext::from(&beta),
            &Randomness::from(&ry),
        );
        // E = s^α · t^γ mod Nˆ
        let E = BigInt::mod_mul(
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
        // big S = s^x · t^m mod Nˆ
        let big_S = BigInt::mod_mul(
            &mod_pow_with_negative(
                &statement.RPParam.s,
                &witness.x,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &m,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        // F = s^β · t^δ mod Nˆ
        let F = BigInt::mod_mul(
            &mod_pow_with_negative(
                &statement.RPParam.s,
                &beta,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &delta,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        // big T = s^y · t^mu mod Nˆ
        let big_T = BigInt::mod_mul(
            &mod_pow_with_negative(
                &statement.RPParam.s,
                &witness.y,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &mu,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        // Hash all prover messages to generate NIZK challenge
        let mut e: BigInt = H::new()
            .chain_bigint(&big_S)
            .chain_bigint(&big_T)
            .chain_bigint(&A)
            .chain_point(&B_x)
            .chain_bigint(&B_y.clone().into())
            .chain_bigint(&E)
            .chain_bigint(&F)
            .result_bigint();
        let mut rng: ChaChaRng =
            ChaChaRng::from_seed(fixed_array::<32>(e.to_bytes()).unwrap());
        let val = rng.gen_range(0..2);
        e = BigInt::from(val)
            .mul(&BigInt::from(-2))
            .add(&BigInt::one())
            .mul(&e);
        // Compute Fiat-Shamir commitment preimage
        let commitment = PiAffGCommitment::<E> {
            A,
            B_x,
            B_y: B_y.clone().into(),
            E,
            F,
            big_S,
            big_T,
        };
        // z1 = α + ex
        let z1 = BigInt::add(&alpha, &e.mul(&witness.x));
        // z2 = β + ey
        let z2 = BigInt::add(&beta, &e.mul(&witness.y));
        // z3 = γ + em
        let z3 = BigInt::add(&gamma, &e.mul(&m));
        // z4 = δ + (e · mu)
        let z4 = BigInt::add(&delta, &e.mul(&mu));
        // w = r · rho^e mod N0
        let w = BigInt::mod_mul(
            &r,
            &mod_pow_with_negative(&witness.rho, &e, &statement.N0),
            &statement.N0,
        );
        // wy = ry · rho_y^e mod N1
        let wy = BigInt::mod_mul(
            &ry,
            &mod_pow_with_negative(&witness.rho_y, &e, &statement.N1),
            &statement.N1,
        );

        Self {
            z1,
            z2,
            z3,
            z4,
            w,
            wy,
            commitment,
            phantom: PhantomData,
        }
    }

    pub fn verify(
        proof: &PiAffGProof<E, H>,
        statement: &PiAffGStatement<E, H>,
    ) -> Result<(), PiAffGError> {
        // Hash all prover messages to generate NIZK challenge
        let mut e: BigInt = H::new()
            .chain_bigint(&proof.commitment.big_S.clone())
            .chain_bigint(&proof.commitment.big_T.clone())
            .chain_bigint(&proof.commitment.A.clone())
            .chain_point(&proof.commitment.B_x.clone())
            .chain_bigint(&proof.commitment.B_y.clone())
            .chain_bigint(&proof.commitment.E.clone())
            .chain_bigint(&proof.commitment.F.clone())
            .result_bigint();
        let mut rng: ChaChaRng =
            ChaChaRng::from_seed(fixed_array::<32>(e.to_bytes()).unwrap());
        let val = rng.gen_range(0..2);
        e = BigInt::from(val)
            .mul(&BigInt::from(-2))
            .add(&BigInt::one())
            .mul(&e);

        /*
            RANGE CHECKS
        */
        // z1 ∈ [-2^{l+ε}, 2^{l+ε}]
        if proof.z1.bit_length() > L_PLUS_EPSILON {
            return Err(PiAffGError::Validation);
        }
        // z2 ∈ [-2^{l'+ε}, 2^{l'+ε}]
        if proof.z2.bit_length() > L_PRIME_PLUS_EPSILON {
            return Err(PiAffGError::Validation);
        }

        /*
            FIRST EQUALITY CHECK
        */
        // C^{z1} · (1 + N0)^{z2} · w^{N0} =A · D^e mod N0^2
        let left_1 = {
            let temp_left_1_1 = Paillier::encrypt_with_chosen_randomness(
                &statement.ek_verifier,
                RawPlaintext::from(&proof.z2),
                &Randomness::from(&proof.w),
            );
            BigInt::mod_mul(
                &mod_pow_with_negative(&statement.C, &proof.z1, &statement.NN0),
                &temp_left_1_1.into(),
                &statement.NN0,
            )
        };
        // A · D^e mod N0^2
        let right_1 = BigInt::mod_mul(
            &proof.commitment.A,
            &mod_pow_with_negative(&statement.D, &e, &statement.NN0),
            &statement.NN0,
        );
        // Assert left == right
        if left_1 != right_1 {
            return Err(PiAffGError::Proof);
        }
        /*
            SECOND EQUALITY CHECK
        */
        // g^{z1} = B_x ·X^e  ∈ G
        let left_2 =
            Point::<E>::generator().as_point() * Scalar::from_bigint(&proof.z1);
        let right_2 = proof.commitment.B_x.clone()
            + (statement.X.clone() * Scalar::from_bigint(&e));
        // Assert left == right
        if left_2 != right_2 {
            return Err(PiAffGError::Proof);
        }
        /*
            THIRD EQUALITY CHECK
        */
        // (1 + N1)^{z2} · wy^{N1} = B_y · Y^e mod N1^2
        let left_3_ciphertext = Paillier::encrypt_with_chosen_randomness(
            &statement.ek_prover,
            RawPlaintext::from(&proof.z2),
            &Randomness::from(&proof.wy),
        );
        let left_3: BigInt = left_3_ciphertext.into();
        // B_y · Y^e mod N1^2
        let right_3 = BigInt::mod_mul(
            &proof.commitment.B_y,
            &mod_pow_with_negative(&statement.Y, &e, &statement.NN1),
            &statement.NN1,
        );
        // Assert left == right
        if left_3.mod_floor(&statement.NN1) != right_3 {
            return Err(PiAffGError::Proof);
        }
        /*
            FOURTH EQUALITY CHECK
        */
        // s^{z1} · t^{z3} = E · big_S^e mod RPParam.N
        let left_4 = {
            // s^{z1} mod RPParam.N^2
            let temp_left_4_1 = mod_pow_with_negative(
                &statement.RPParam.s,
                &proof.z1,
                &statement.RPParam.N,
            );
            // t^{z3} mod RPParam.N^2
            let temp_left_4_2 = mod_pow_with_negative(
                &statement.RPParam.t,
                &proof.z3,
                &statement.RPParam.N,
            );
            // s^{z1} · t^{z3} mod RPParam.N^2
            BigInt::mod_mul(
                &temp_left_4_1,
                &temp_left_4_2,
                &statement.RPParam.N,
            )
        };
        // E · big_S^e mod RPParam.N^2
        let right_4 = BigInt::mod_mul(
            &proof.commitment.E,
            &mod_pow_with_negative(
                &proof.commitment.big_S,
                &e,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        // Assert left == right
        if left_4 != right_4 {
            return Err(PiAffGError::Proof);
        }
        /*
            FIFTH EQUALITY CHECK
        */
        // s^{z2} · t^{z4} = F · big_T^e mod RPParam.N
        let left_5 = {
            // s^{z2} mod RPParam.N^2
            let temp_left_5_1 = mod_pow_with_negative(
                &statement.RPParam.s,
                &proof.z2,
                &statement.RPParam.N,
            );
            // t^{z4} mod RPParam.N^2
            let temp_left_5_2 = mod_pow_with_negative(
                &statement.RPParam.t,
                &proof.z4,
                &statement.RPParam.N,
            );
            // s^{z2} · t^{z4} mod RPParam.N^2
            BigInt::mod_mul(
                &temp_left_5_1,
                &temp_left_5_2,
                &statement.RPParam.N,
            )
        };
        // F · big_T^e mod RPParam.N^2
        let right_5 = BigInt::mod_mul(
            &proof.commitment.F,
            &mod_pow_with_negative(
                &proof.commitment.big_T,
                &e,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        // Assert left == right
        if left_5 != right_5 {
            return Err(PiAffGError::Proof);
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
    fn test_affine_g_proof() {
        let (rpparam, _) = generate_safe_h1_h2_N_tilde();
        let (ek_prover, _) =
            Paillier::keypair_with_modulus_size(BITS_PAILLIER).keys();
        let (ek_verifier, _) =
            Paillier::keypair_with_modulus_size(BITS_PAILLIER).keys();

        let rho: BigInt = sample_relatively_prime_integer(&ek_verifier.n);
        let rho_y: BigInt = sample_relatively_prime_integer(&ek_prover.n);
        let C = Paillier::encrypt(
            &ek_verifier,
            RawPlaintext::from(BigInt::from(12)),
        );
        let (statement, witness) =
            PiAffGStatement::<Secp256k1, Sha256>::generate(
                rpparam,
                rho,
                rho_y,
                ek_prover,
                ek_verifier,
                C.0.into_owned(),
            );
        let proof =
            PiAffGProof::<Secp256k1, Sha256>::prove(&witness, &statement);
        assert!(PiAffGProof::<Secp256k1, Sha256>::verify(&proof, &statement)
            .is_ok());
    }
}
