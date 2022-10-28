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

use super::sample_relatively_prime_integer;
use crate::{
	utilities::{mod_pow_with_negative, L, L_PLUS_EPSILON, L_PRIME, L_PRIME_PLUS_EPSILON},
	Error,
};
use curv::{
	arithmetic::{traits::*, Modulo},
	cryptographic_primitives::hashing::{Digest, DigestExt},
	elliptic::curves::{Curve, Point, Scalar},
	BigInt,
};
use paillier::{EncryptWithChosenRandomness, EncryptionKey, Paillier, Randomness, RawPlaintext};
use rand::Rng;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierMulStatement<E: Curve, H: Digest + Clone> {
	N: BigInt,
	NN: BigInt,
	C: BigInt,
	Y: BigInt,
	X: Point<E>,
	ek_prover: EncryptionKey,
	ek_verifier: EncryptionKey,
	phantom: PhantomData<(E, H)>,
}

pub struct PaillierMulWitness<E: Curve, H: Digest + Clone> {
	x: BigInt,
	rho: BigInt,
	rho_x: BigInt,
	phantom: PhantomData<(E, H)>,
}

impl<E: Curve, H: Digest + Clone> PaillierMulStatement<E, H> {
	#[allow(clippy::too_many_arguments)]
	pub fn generate(
		rho: BigInt,
		rho_x: BigInt,
		prover: EncryptionKey,
		verifier: EncryptionKey,
		C: BigInt,
	) -> (Self, PaillierMulWitness<E, H>) {

	}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierMulCommitment<E: Curve> {
	A: BigInt,
	B: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierMulProof<E: Curve, H: Digest + Clone> {
	z: BigInt,
    u: BigInt,
    v: BigInt,
	commitment: PaillierMulCommitment<E>,
	phantom: PhantomData<(E, H)>,
}

// Link to the UC non-interactive threshold ECDSA paper
impl<E: Curve, H: Digest + Clone> PaillierMulProof<E, H> {
	pub fn prove(
		witness: &PaillierMulWitness<E, H>,
		statement: &PaillierMulStatement<E, H>,
	) -> PaillierMulProof<E, H> {
		
	}

	pub fn verify(
		proof: &PaillierMulProof<E, H>,
		statement: &PaillierMulStatement<E, H>,
	) -> Result<(), Error> {

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utilities::{mta::range_proofs::SampleFromMultiplicativeGroup, BITS_PAILLIER};
	use curv::elliptic::curves::secp256_k1::Secp256k1;
	use fs_dkr::ring_pedersen_proof::RingPedersenStatement;
	use paillier::{Encrypt, KeyGeneration, Paillier, RawPlaintext};
	use sha2::Sha256;

	#[test]
	fn test_affine_g_proof() {
		let (ring_pedersen_statement, _witness) =
			RingPedersenStatement::<Secp256k1, Sha256>::generate();
		let (ek_prover, _) = Paillier::keypair_with_modulus_size(BITS_PAILLIER).keys();
		let (ek_verifier, _) = Paillier::keypair_with_modulus_size(BITS_PAILLIER).keys();

		let rho: BigInt = BigInt::from_paillier_key(&ek_verifier);
		let rho_y: BigInt = BigInt::from_paillier_key(&ek_prover);
		let C = Paillier::encrypt(&ek_verifier, RawPlaintext::from(BigInt::from(12)));
		let (statement, witness) =
			PaillierMulStatement::<Secp256k1, Sha256>::generate(
				rho,
				rho_y,
				ring_pedersen_statement.S,
				ring_pedersen_statement.T,
				ring_pedersen_statement.N,
				ek_prover,
				ek_verifier,
				C.0.into_owned(),
			);
		let proof = PaillierMulProof::<Secp256k1, Sha256>::prove(
			&witness, &statement,
		);
		assert!(PaillierMulProof::<Secp256k1, Sha256>::verify(
			&proof, &statement
		)
		.is_ok());
	}
}
