#![allow(non_snake_case)]
/*
	Paillier Affine Operation with Group Commitment in Range.
	Copyright 2022 by Webb Technologies.

	cggmp-threshold-ecdsa is free software: you can redistribute
	it and/or modify it under the terms of the GNU General Public
	License as published by the Free Software Foundation, either
	version 3 of the License, or (at your option) any later version.
	@license GPL-3.0+ <https://github.com/webb-tools/cggmp-threshold-ecdsa/blob/master/LICENSE>
*/

//! For parameters (G, g, N0, N1), consisting of element g and in group G and Paillier
//! public keys N0, N1, verify the ciphertext C \in Z∗_{N0^2} was obtained as an affine-like
//! transformation on C0 such that the multiplicative coefficient (i.e. ε) is equal to the
//! exponent of X ∈ G in the range I, and the additive coefficient (i.e. δ) is equal to the
//! plaintext-value of Y ∈ Z_N1 and resides in the the range J.

//! Setup: Auxiliary Paillier Modulus Nˆ and Ring-Pedersen parameters s, t ∈ Z∗_{Nˆ}.
//!
//! Inputs: Common input is (G,g,N0,N1,C,D,Y,X) where q = |G| and g is a generator of G.
//! The Prover has secret input (x,y,ρ,ρy) such that
//!             x∈±2l, y∈±2l′, g^{x} = X, (1+N1)^{y}ρ^{N1} = Y mod N2,
//! and
//!             D=C^{x}(1+N0)^{y}·ρ^{N0} mod N0^{2}.

use curv::{
	arithmetic::{traits::*, Modulo, NumberTests},
	cryptographic_primitives::hashing::{Digest, DigestExt},
	elliptic::curves::{Curve, Point, Scalar},
	BigInt,
};
use paillier::EncryptionKey;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use crate::Error;

use super::sample_relatively_prime_integer;

pub fn mod_pow_with_negative(v: &BigInt, pow: &BigInt, modulus: &BigInt) -> BigInt {
	if BigInt::is_negative(pow) {
		let v_inv = BigInt::mod_inv(v, modulus).unwrap();
		let pow_abs = BigInt::abs(pow);
		BigInt::mod_pow(&v_inv, &pow_abs, modulus)
	} else {
		BigInt::mod_pow(v, pow, modulus)
	}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AffineWithGroupComRangeStatement<E: Curve, H: Digest + Clone> {
	S: BigInt,
	T: BigInt,
	N_hat: BigInt,
	N0: BigInt,
	N1: BigInt,
	NN0: BigInt,
	NN1: BigInt,
	C: BigInt,
	D: BigInt,
	Y: BigInt,
	X: Point<E>,
	phantom: PhantomData<(E, H)>,
}

pub struct AffineWithGroupComRangeWitness<E: Curve, H: Digest + Clone> {
	x: BigInt,
	y: BigInt,
	rho: BigInt,
	rho_y: BigInt,
	phantom: PhantomData<(E, H)>,
}

impl<E: Curve, H: Digest + Clone> AffineWithGroupComRangeStatement<E, H> {
	pub fn generate(
		rho: BigInt,
		rho_y: BigInt,
		S: BigInt,
		T: BigInt,
		N_hat: BigInt,
		prover: EncryptionKey,
		verifier: EncryptionKey,
		C: BigInt,
	) -> (Self, AffineWithGroupComRangeWitness<E, H>) {
		let N0 = prover.n;
		let N1 = verifier.n;
		let x = BigInt::sample_range(
			&(BigInt::from(-1)
				.mul(&BigInt::pow(&BigInt::from(2), &2 * crate::utilities::L as u32))),
			&BigInt::pow(&BigInt::from(2), &2 * crate::utilities::L as u32),
		);
		let y = BigInt::sample_range(
			&(BigInt::from(-1)
				.mul(&BigInt::pow(&BigInt::from(2), &2 * crate::utilities::L_PRIME as u32))),
			&BigInt::pow(&BigInt::from(2), &2 * crate::utilities::L_PRIME as u32),
		);

		let X = Point::<E>::generator().as_point() * Scalar::from(&x);
		// Compute Y
		let temp_Y_1 = mod_pow_with_negative(&BigInt::from(1).add(&N1), &y, &verifier.nn);
		let temp_Y_2 = BigInt::mod_pow(&rho_y, &N1, &verifier.nn);
		let Y = BigInt::mod_mul(&temp_Y_1, &temp_Y_2, &verifier.nn);
		// (1 + N0)^y mod N0^2
		let temp_D_1 = mod_pow_with_negative(&BigInt::from(1).add(&N0), &y, &prover.nn);
		// rho^N0 mod N0^2
		let temp_D_2 = BigInt::mod_pow(&rho, &N0, &prover.nn);
		// (1 + N0)^y · rho^N0 mod N0^2
		let temp_D_3 = BigInt::mod_mul(&temp_D_1, &temp_D_2, &prover.nn);
		// D = C^x · (1 + N0)^y · rho^N0 mod N0^2
		let D = BigInt::mod_mul(
			&mod_pow_with_negative(&C, &x, &prover.nn),
			&temp_D_3,
			&prover.nn.clone(),
		);

		(
			Self {
				S,
				T,
				N_hat,
				N0,
				N1,
				NN0: prover.nn,
				NN1: verifier.nn,
				C,
				D,
				Y,
				X,
				phantom: PhantomData,
			},
			AffineWithGroupComRangeWitness { x, y, rho, rho_y, phantom: PhantomData },
		)
	}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AffineWithGroupComRangeCommitment<E: Curve> {
	A: BigInt,
	B_x: Point<E>,
	B_y: BigInt,
	E: BigInt,
	F: BigInt,
	big_S: BigInt,
	big_T: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AffineWithGroupComRangeProof<E: Curve, H: Digest + Clone> {
	z1: BigInt,
	z2: BigInt,
	z3: BigInt,
	z4: BigInt,
	w: BigInt,
	wy: BigInt,
	commitment: AffineWithGroupComRangeCommitment<E>,
	phantom: PhantomData<(E, H)>,
}

// Link to the UC non-interactive threshold ECDSA paper
impl<E: Curve, H: Digest + Clone> AffineWithGroupComRangeProof<E, H> {
	pub fn prove(
		witness: &AffineWithGroupComRangeWitness<E, H>,
		statement: &AffineWithGroupComRangeStatement<E, H>,
	) -> AffineWithGroupComRangeProof<E, H> {
		// Set up exponents
		let l_exp = BigInt::pow(&BigInt::from(2), crate::utilities::L as u32);
		let lplus_exp = BigInt::pow(&BigInt::from(2), crate::utilities::L_PLUS_EPSILON as u32);
		let L_PRIMEplus_exp =
			BigInt::pow(&BigInt::from(2), crate::utilities::L_PRIME_PLUS_EPSILON as u32);

		// α ← ± 2^{l+ε}
		let alpha = BigInt::sample_range(&BigInt::from(-1).mul(&lplus_exp), &lplus_exp);
		// β ← ± 2^{l'+ε}
		let beta = BigInt::sample_range(&BigInt::from(-1).mul(&L_PRIMEplus_exp), &L_PRIMEplus_exp);
		// Sample r, ry as unit values from Z_N0, Z_N1
		let r = sample_relatively_prime_integer(&statement.N0);
		let ry = sample_relatively_prime_integer(&statement.N1);
		// γ ← ± 2^{l+ε} · Nˆ
		let gamma = BigInt::sample_range(
			&BigInt::from(-1).mul(&lplus_exp).mul(&statement.N_hat),
			&lplus_exp.mul(&statement.N_hat),
		);

		// m ← ± 2l · Nˆ
		let m = BigInt::sample_range(
			&BigInt::from(-1).mul(&l_exp).mul(&statement.N_hat),
			&l_exp.mul(&statement.N_hat),
		);
		// δ ← ± 2^{l+ε} · Nˆ
		let delta = BigInt::sample_range(
			&BigInt::from(-1).mul(&lplus_exp).mul(&statement.N_hat),
			&lplus_exp.mul(&statement.N_hat),
		);

		// mu ← ± 2l · Nˆ
		let mu = BigInt::sample_range(
			&BigInt::from(-1).mul(&l_exp).mul(&statement.N_hat),
			&l_exp.mul(&statement.N_hat),
		);

		// A = C^α · (1 + N0)^y · r^N0 mod N0^2
		let A = {
			// (1 + N0)^β mod N0^2
			let temp_A_1 =
				mod_pow_with_negative(&BigInt::from(1).add(&statement.N0), &beta, &statement.NN0);
			// r^N0 mod N0^2
			let temp_A_2 = BigInt::mod_pow(&r, &statement.N0, &statement.NN0);
			// A = C^α · (1 + N0)^β · r^N0 mod N0^2
			BigInt::mod_mul(
				&mod_pow_with_negative(&statement.C, &alpha, &statement.NN0),
				&BigInt::mod_mul(&temp_A_1, &temp_A_2, &statement.NN0),
				&statement.NN0,
			)
		};

		let B_x: Point<E> = Point::<E>::generator().as_point() * Scalar::from_bigint(&alpha);
		// By = (1 + N1)^β · ry^N1 mod N1^2
		let B_y = {
			// (1 + N1)^β mod N1^2
			let temp_B_1 =
				mod_pow_with_negative(&BigInt::from(1).add(&statement.N1), &beta, &statement.NN1);
			// ry^N1 mod N1^2
			let temp_B_2 = BigInt::mod_pow(&ry, &statement.N1, &statement.NN1);
			// B = (1 + N1)^β · ry^N1 mod N1^2
			&BigInt::mod_mul(&temp_B_1, &temp_B_2, &statement.NN1)
		};
		// E = s^α · t^γ mod Nˆ
		let E = BigInt::mod_mul(
			&mod_pow_with_negative(&statement.S, &alpha, &statement.N_hat),
			&mod_pow_with_negative(&statement.T, &gamma, &statement.N_hat),
			&statement.N_hat,
		);
		// big S = s^x · t^m mod Nˆ
		let big_S = BigInt::mod_mul(
			&mod_pow_with_negative(&statement.S, &witness.x, &statement.N_hat),
			&mod_pow_with_negative(&statement.T, &m, &statement.N_hat),
			&statement.N_hat,
		);
		// F = s^β · t^δ mod Nˆ
		let F = BigInt::mod_mul(
			&mod_pow_with_negative(&statement.S, &beta, &statement.N_hat),
			&mod_pow_with_negative(&statement.T, &delta, &statement.N_hat),
			&statement.N_hat,
		);
		// big T = s^y · t^mu mod Nˆ
		let big_T = BigInt::mod_mul(
			&mod_pow_with_negative(&statement.S, &witness.y, &statement.N_hat),
			&mod_pow_with_negative(&statement.T, &mu, &statement.N_hat),
			&statement.N_hat,
		);
		// Hash all prover messages to generate NIZK challenge
		let e: BigInt = H::new()
			.chain_bigint(&big_S)
			.chain_bigint(&big_T)
			.chain_bigint(&A)
			.chain_point(&B_x)
			.chain_bigint(B_y)
			.chain_bigint(&E)
			.chain_bigint(&F)
			.result_bigint();

		let commitment =
			AffineWithGroupComRangeCommitment::<E> { A, B_x, B_y: B_y.clone(), E, F, big_S, big_T };
		// z1 = α + ex
		let z1 = BigInt::add(&alpha, &e.mul(&witness.x));
		// z2 = β + ey
		let z2 = BigInt::add(&beta, &e.mul(&witness.y));
		// z3 = γ + em
		let z3 = BigInt::add(&gamma, &e.mul(&m));
		// z4 = δ + (e · mu)
		let z4 = BigInt::add(&delta, &e.mul(&mu));
		// w = r · rho^e mod N0
		let w =
			BigInt::mod_mul(&r, &BigInt::mod_pow(&witness.rho, &e, &statement.N0), &statement.N0);
		// wy = ry · rho_y^e mod N1
		let wy = BigInt::mod_mul(
			&ry,
			&BigInt::mod_pow(&witness.rho_y, &e, &statement.N1),
			&statement.N1,
		);

		Self { z1, z2, z3, z4, w, wy, commitment, phantom: PhantomData }
	}

	pub fn verify(
		proof: &AffineWithGroupComRangeProof<E, H>,
		statement: &AffineWithGroupComRangeStatement<E, H>,
	) -> Result<(), Error> {
		// Hash all prover messages to generate NIZK challenge
		let e: BigInt = H::new()
			.chain_bigint(&proof.commitment.big_S.clone())
			.chain_bigint(&proof.commitment.big_T.clone())
			.chain_bigint(&proof.commitment.A.clone())
			.chain_point(&proof.commitment.B_x.clone())
			.chain_bigint(&proof.commitment.B_y.clone())
			.chain_bigint(&proof.commitment.E.clone())
			.chain_bigint(&proof.commitment.F.clone())
			.result_bigint();
		/*
			FIRST EQUALITY CHECK
		*/
		// C^{z1} · (1 + N)^{z2} · w^{N0} =A · D^e mod N0^2
		let left_1 = {
			// (1 + N)^{z2} mod N0^2
			let temp_left_1_1 = mod_pow_with_negative(
				&BigInt::from(1).add(&statement.N0),
				&proof.z2,
				&statement.NN0,
			);
			// w^{N0} mod N0^2
			let temp_left_1_2 = BigInt::mod_pow(&proof.w, &statement.N0, &statement.NN0);
			// C^{z1} · (1 + N)^{z2} · w^{N0} mod N0^2
			BigInt::mod_mul(
				&mod_pow_with_negative(&statement.C, &proof.z1, &statement.NN0),
				&BigInt::mod_mul(&temp_left_1_1, &temp_left_1_2, &statement.NN0),
				&statement.NN0,
			)
		};
		// A · D^e mod N0^2
		let right_1 = BigInt::mod_mul(
			&proof.commitment.A,
			&BigInt::mod_pow(&statement.D, &e, &statement.NN0),
			&statement.NN0,
		);
		// Assert left == right
		assert!(left_1 == right_1);
		/*
			SECOND EQUALITY CHECK
		*/
		// g^{z1} = B_x ·X^e  ∈ G
		let left_2 = Point::<E>::generator().as_point() * Scalar::from_bigint(&proof.z1);
		let right_2 =
			proof.commitment.B_x.clone() + (statement.X.clone() * Scalar::from_bigint(&e));
		// Assert left == right
		assert!(left_2 == right_2);
		/*
			THIRD EQUALITY CHECK
		*/
		// (1 + N1)^{z2} · wy^{N1} = B_y · Y^e mod N1^2
		let left_3 = {
			// (1 + N1)^{z2} mod N1^2
			let temp_left_3_1 = mod_pow_with_negative(
				&BigInt::from(1).add(&statement.N1),
				&proof.z2,
				&statement.NN1,
			);
			// wy^{N1} mod N1^2
			let temp_left_3_2 = BigInt::mod_pow(&proof.wy, &statement.N1, &statement.NN1);
			// (1 + N1)^{z2} · wy^{N1} mod N1^2
			BigInt::mod_mul(&temp_left_3_1, &temp_left_3_2, &statement.NN1)
		};
		// B_y · Y^e mod N1^2
		let right_3 = BigInt::mod_add(
			&proof.commitment.B_y,
			&BigInt::mod_pow(&statement.Y, &e, &statement.NN1),
			&statement.NN1,
		);
		// Assert left == right
		assert!(left_3 == right_3, "{:?} != {:?}", left_3, right_3);
		/*
			FOURTH EQUALITY CHECK
		*/
		// s^{z1} · t^{z3} = E · big_S^e mod N_hat
		let left_4 = {
			// s^{z1} mod N_hat^2
			let temp_left_4_1 = BigInt::mod_pow(&statement.S, &proof.z1, &statement.N_hat);
			// t^{z3} mod N_hat^2
			let temp_left_4_2 = BigInt::mod_pow(&statement.T, &proof.z3, &statement.N_hat);
			// s^{z1} · t^{z3} mod N_hat^2
			BigInt::mod_mul(&temp_left_4_1, &temp_left_4_2, &statement.N_hat)
		};
		// E · big_S^e mod N_hat^2
		let right_4 = BigInt::mod_mul(
			&proof.commitment.E,
			&BigInt::mod_pow(&proof.commitment.big_S, &e, &statement.N_hat),
			&statement.N_hat,
		);
		// Assert left == right
		assert!(left_4 == right_4);
		/*
			FIFTH EQUALITY CHECK
		*/
		// s^{z2} · t^{z4} = F · big_T^e mod N_hat
		let left_5 = {
			// s^{z2} mod N_hat^2
			let temp_left_5_1 = BigInt::mod_pow(&statement.S, &proof.z2, &statement.N_hat);
			// t^{z4} mod N_hat^2
			let temp_left_5_2 = BigInt::mod_pow(&statement.T, &proof.z4, &statement.N_hat);
			// s^{z2} · t^{z4} mod N_hat^2
			BigInt::mod_mul(&temp_left_5_1, &temp_left_5_2, &statement.N_hat)
		};
		// F · big_T^e mod N_hat^2
		let right_5 = BigInt::mod_mul(
			&proof.commitment.F,
			&BigInt::mod_pow(&proof.commitment.big_T, &e, &statement.N_hat),
			&statement.N_hat,
		);
		// Assert left == right
		assert!(left_5 == right_5);
		/*
			RANGE CHECKS
		*/
		// z1 ∈ [-2^{l+ε}, 2^{l+ε}]
		assert!(proof.z1 >= BigInt::from(-2).pow(crate::utilities::L_PLUS_EPSILON as u32));
		assert!(proof.z1 <= BigInt::from(2).pow(crate::utilities::L_PLUS_EPSILON as u32));
		// z2 ∈ [-2^{l'+ε}, 2^{l'+ε}]
		assert!(proof.z2 >= BigInt::from(-2).pow(crate::utilities::L_PRIME_PLUS_EPSILON as u32));
		assert!(proof.z2 <= BigInt::from(2).pow(crate::utilities::L_PRIME_PLUS_EPSILON as u32));

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utilities::mta::range_proofs::SampleFromMultiplicativeGroup;
	use curv::elliptic::curves::secp256_k1::Secp256k1;
	use fs_dkr::ring_pedersen_proof::RingPedersenStatement;
	use paillier::{
		EncryptWithChosenRandomness, KeyGeneration, Paillier, Randomness, RawPlaintext,
	};
	use sha2::Sha256;

	#[test]
	fn test_affine_g_proof() {
		let (statement, _) = RingPedersenStatement::<Secp256k1, Sha256>::generate();
		let ek_prover = statement.ek.clone();
		let (ek_verifier, _) =
			Paillier::keypair_with_modulus_size(fs_dkr::PAILLIER_KEY_SIZE).keys();

		let rho: BigInt = BigInt::from_paillier_key(&ek_prover);
		let rho_y: BigInt = BigInt::from_paillier_key(&ek_verifier);
		let c = RawPlaintext::from(BigInt::from(1));
		let C =
			Paillier::encrypt_with_chosen_randomness(&ek_prover, c, &Randomness::from(rho.clone()));
		let S: BigInt = statement.S;
		let T: BigInt = statement.T;
		let N_hat: BigInt = ek_prover.n.clone();
		let (statement, witness) = AffineWithGroupComRangeStatement::<Secp256k1, Sha256>::generate(
			rho,
			rho_y,
			S,
			T,
			N_hat,
			ek_prover,
			ek_verifier,
			C.0.into_owned(),
		);
		let proof = AffineWithGroupComRangeProof::<Secp256k1, Sha256>::prove(&witness, &statement);
		assert!(
			AffineWithGroupComRangeProof::<Secp256k1, Sha256>::verify(&proof, &statement).is_ok()
		);
	}
}
