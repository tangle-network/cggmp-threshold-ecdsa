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

use curv::{
	arithmetic::traits::*,
	cryptographic_primitives::hashing::{Digest, DigestExt},
	elliptic::curves::Curve,
	BigInt,
};
use paillier::{EncryptWithChosenRandomness, EncryptionKey, Paillier, Randomness, RawPlaintext};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use zk_paillier::zkproofs::IncorrectProof;

use super::{mod_pow_with_negative, sample_relatively_prime_integer};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierEncryptionInRangeSetupParameters<E: Curve, H: Digest + Clone> {
	s: BigInt,
	t: BigInt,
	N_hat: BigInt,
	phantom: PhantomData<(E, H)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierEncryptionInRangeCommonInput<E: Curve, H: Digest + Clone> {
	N0: BigInt,
	NN0: BigInt,
	K: BigInt,
	phantom: PhantomData<(E, H)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierEncryptionInRangeWitness<E: Curve, H: Digest + Clone> {
	k: BigInt,
	rho: BigInt,
	phantom: PhantomData<(E, H)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierEncryptionInRangeProof<E: Curve, H: Digest + Clone> {
	S: BigInt,
	A: BigInt,
	C: BigInt,
	z_1: BigInt,
	z_2: BigInt,
	z_3: BigInt,
	phantom: PhantomData<(E, H)>,
}

impl<E: Curve, H: Digest + Clone> PaillierEncryptionInRangeProof<E, H> {
	#[allow(dead_code)]
	fn prove(
		witness: &PaillierEncryptionInRangeWitness<E, H>,
		common_input: &PaillierEncryptionInRangeCommonInput<E, H>,
		setup_parameters: &PaillierEncryptionInRangeSetupParameters<E, H>,
	) -> Self {
		// Step 1: Sample alpha between -2^{L+eps} and 2^{L+eps}
		let alpha_upper = BigInt::pow(&BigInt::from(2), crate::utilities::L_PLUS_EPSILON as u32);
		let alpha_lower = BigInt::from(-1).mul(&alpha_upper);
		let alpha = BigInt::sample_range(&alpha_lower, &alpha_upper);

		// Step 2: mu, r, gamma
		// Sample mu between -2^L * N_hat and 2^L * N_hat
		let mu_upper = BigInt::mul(
			&setup_parameters.N_hat,
			&BigInt::pow(&BigInt::from(2), crate::utilities::L as u32),
		);
		let mu_lower = BigInt::from(-1).mul(&mu_upper);
		let mu = BigInt::sample_range(&mu_lower, &mu_upper);

		// γ ← ± 2^{l+ε} · Nˆ
		let gamma_upper = BigInt::mul(
			&setup_parameters.N_hat,
			&BigInt::pow(&BigInt::from(2), crate::utilities::L_PLUS_EPSILON as u32),
		);
		let gamma_lower = BigInt::from(-1).mul(&mu_upper);
		let gamma = BigInt::sample_range(&gamma_lower, &gamma_upper);
		// Sample r from Z*_{N_0}
		let r = sample_relatively_prime_integer(&common_input.N0.clone());

		// Step 3: S, A, C
		// S = s^k t^mu mod N_hat
		let S = BigInt::mod_mul(
			&mod_pow_with_negative(&setup_parameters.s, &witness.k, &setup_parameters.N_hat),
			&mod_pow_with_negative(&setup_parameters.t, &mu, &setup_parameters.N_hat),
			&setup_parameters.N_hat,
		);

		// A = (1+N_0)^{alpha}r^{N_0} mod N_0^2
		let A: BigInt = Paillier::encrypt_with_chosen_randomness(
			&EncryptionKey { n: common_input.N0.clone(), nn: common_input.NN0.clone() },
			RawPlaintext::from(&alpha),
			&Randomness::from(&r),
		)
		.into();

		// C = s^alpha * t^gamma mod N_hat
		let C = BigInt::mod_mul(
			&mod_pow_with_negative(&setup_parameters.s, &alpha, &setup_parameters.N_hat),
			&mod_pow_with_negative(&setup_parameters.t, &gamma, &setup_parameters.N_hat),
			&setup_parameters.N_hat,
		);

		// Step 4: Hash S, A, C
		let e = H::new().chain_bigint(&S).chain_bigint(&A).chain_bigint(&C).result_bigint();

		// Step 5: Compute z_1, z_2, z_3
		// z_1 = alpha + ek
		let z_1 = BigInt::add(&alpha, &BigInt::mul(&e, &witness.k));
		// z_2 = r * rho^2 mod N_0
		let z_2 = BigInt::mod_mul(
			&r,
			&mod_pow_with_negative(&witness.rho, &e, &common_input.N0),
			&common_input.N0,
		);
		// z_3 = gamma + e*mu
		let z_3 = BigInt::add(&gamma, &BigInt::mul(&e, &mu));

		Self { S, A, C, z_1, z_2, z_3, phantom: PhantomData }
	}

	#[allow(dead_code)]
	fn verify(
		proof: &PaillierEncryptionInRangeProof<E, H>,
		common_input: &PaillierEncryptionInRangeCommonInput<E, H>,
		setup_parameters: &PaillierEncryptionInRangeSetupParameters<E, H>,
	) -> Result<(), IncorrectProof> {
		let e = H::new()
			.chain_bigint(&proof.S)
			.chain_bigint(&proof.A)
			.chain_bigint(&proof.C)
			.result_bigint();

		// Equality Checks
		let NN0 = common_input.NN0.clone();
		// left_1 = (1+N_0)^{z_1}z_2^{N_0} mod N_0^2
		let left_1: BigInt = Paillier::encrypt_with_chosen_randomness(
			&EncryptionKey { n: common_input.N0.clone(), nn: NN0.clone() },
			RawPlaintext::from(&proof.z_1),
			&Randomness::from(&proof.z_2),
		)
		.into();
		// right_1 = A * K^2 mod N_0^2
		let right_1 =
			BigInt::mod_mul(&proof.A, &mod_pow_with_negative(&common_input.K, &e, &NN0), &NN0);

		// left_2 = s^z_1 t^z_3 mod N_hat
		let left_2 = BigInt::mod_mul(
			&mod_pow_with_negative(&setup_parameters.s, &proof.z_1, &setup_parameters.N_hat),
			&mod_pow_with_negative(&setup_parameters.t, &proof.z_3, &setup_parameters.N_hat),
			&setup_parameters.N_hat,
		);
		// right_2 = C * S^e mod N_hat
		let right_2 = BigInt::mod_mul(
			&proof.C,
			&mod_pow_with_negative(&proof.S, &e, &setup_parameters.N_hat),
			&setup_parameters.N_hat,
		);

		if left_1.mod_floor(&NN0) != right_1 || left_2 != right_2 {
			return Err(IncorrectProof)
		}

		// Range Check -2^{L + eps} <= z_1 <= 2^{L+eps}
		let lower_bound_check: bool = proof.z_1 >=
			BigInt::from(-1)
				.mul(&BigInt::pow(&BigInt::from(2), crate::utilities::L_PLUS_EPSILON as u32));

		let upper_bound_check =
			proof.z_1 <= BigInt::pow(&BigInt::from(2), crate::utilities::L_PLUS_EPSILON as u32);

		if !(lower_bound_check && upper_bound_check) {
			return Err(IncorrectProof)
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use curv::elliptic::curves::{secp256_k1::Secp256k1, Scalar};
	use paillier::{KeyGeneration, Paillier};
	use sha2::Sha256;

	const PAILLIER_KEY_SIZE: usize = 2048;

	fn generate_test_values() -> (
		PaillierEncryptionInRangeWitness<Secp256k1, Sha256>,
		PaillierEncryptionInRangeCommonInput<Secp256k1, Sha256>,
		PaillierEncryptionInRangeSetupParameters<Secp256k1, Sha256>,
	) {
		let (ek_tilde, dk_tilde) = Paillier::keypair_with_modulus_size(PAILLIER_KEY_SIZE).keys();
		let one = BigInt::one();
		let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
		let r = BigInt::sample_below(&ek_tilde.n);
		let lambda = BigInt::sample_below(&phi);
		let t = mod_pow_with_negative(&r, &BigInt::from(2), &ek_tilde.n);
		let s = mod_pow_with_negative(&t, &lambda, &ek_tilde.n);
		let k = BigInt::sample_below(Scalar::<Secp256k1>::group_order());
		let rho = sample_relatively_prime_integer(&ek_tilde.n);
		let K = BigInt::mod_mul(
			&mod_pow_with_negative(&BigInt::add(&one, &ek_tilde.n), &k, &ek_tilde.nn),
			&mod_pow_with_negative(&rho, &ek_tilde.n, &ek_tilde.nn),
			&ek_tilde.nn,
		);

		(
			PaillierEncryptionInRangeWitness { k, rho, phantom: PhantomData },
			PaillierEncryptionInRangeCommonInput {
				N0: ek_tilde.n.clone(),
				NN0: ek_tilde.nn,
				K,
				phantom: PhantomData,
			},
			PaillierEncryptionInRangeSetupParameters {
				s,
				t,
				N_hat: ek_tilde.n,
				phantom: PhantomData,
			},
		)
	}

	#[test]
	fn test_paillier_encryption_in_range_proof() {
		let (witness, common_input, setup_parameters) = generate_test_values();
		let proof = PaillierEncryptionInRangeProof::<Secp256k1, Sha256>::prove(
			&witness,
			&common_input,
			&setup_parameters,
		);
		assert!(PaillierEncryptionInRangeProof::<Secp256k1, Sha256>::verify(
			&proof,
			&common_input,
			&setup_parameters
		)
		.is_ok());
	}
}
