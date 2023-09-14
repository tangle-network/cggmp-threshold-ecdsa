#![allow(non_snake_case)]

use curv::{
	arithmetic::traits::*,
	cryptographic_primitives::hashing::{Digest, DigestExt},
	elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
	BigInt,
};
use fs_dkr::PAILLIER_KEY_SIZE;
use paillier::{EncryptionKey, Paillier};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512Trunc256};
use thiserror::Error;

use crate::party_i::Keys;

pub const ITERATIONS: usize = 128;

#[derive(Error, Debug)]
pub enum DlnProofError {
	#[error("dlnproof verification failed")]
	Verify,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DlnProofStatement {
	pub ek: EncryptionKey,
	pub h1: BigInt,
	pub h2: BigInt,
	pub N_tilde: BigInt,
}

impl DlnProofStatement {
	pub fn generate() -> Self {
		let key = Keys::create(0);
		DlnProofStatement { ek: key.ek, h1: key.h1, h2: key.h2, N_tilde: key.N_tilde }
	}
}

#[derive(Clone)]
pub struct DlnProofWitness {
	pub x: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlnProof {
	Alpha: Vec<BigInt>,
	T: Vec<BigInt>,
}

impl DlnProof {
	pub fn prove(witness: &DlnProofWitness, statement: &DlnProofStatement) -> Self {
		let mut a: Vec<BigInt> = vec![BigInt::zero(); ITERATIONS];
		let mut alpha: Vec<BigInt> = vec![BigInt::zero(); ITERATIONS];
		for i in 0..ITERATIONS {
			a[i] = BigInt::sample_below(&statement.ek.n);
			alpha[i] = BigInt::mod_pow(&statement.h1, &a[i], &statement.N_tilde);
		}

		let mut msg: Vec<&BigInt> = vec![&statement.h1, &statement.h2, &statement.N_tilde];
		for i in 0..ITERATIONS {
			msg.push(&alpha[i]);
		}

		let mut hash = Sha512Trunc256::new();
		for elt in msg.iter() {
			hash = hash.chain_bigint(&elt);
		}

		let c: Vec<_> = hash
			.result_bigint()
			.to_bytes()
			.into_iter()
			.flat_map(|val| {
				[
					(val >> 7) & 1,
					(val >> 6) & 1,
					(val >> 5) & 1,
					(val >> 4) & 1,
					(val >> 3) & 1,
					(val >> 2) & 1,
					(val >> 1) & 1,
					(val >> 0) & 1,
				]
				.into_iter()
			})
			.collect();

		let mut t: Vec<BigInt> = vec![BigInt::zero(); ITERATIONS];
		for i in 0..ITERATIONS {
			let c_i = BigInt::from(c[i] as u16);
			let rhs = BigInt::mod_mul(&c_i, &witness.x, &statement.ek.n);
			t[i] = BigInt::mod_add(&a[i], &rhs, &statement.ek.n);
		}

		DlnProof { Alpha: alpha, T: t }
	}

	pub fn verify(&self, statement: &DlnProofStatement) -> Result<(), DlnProofError> {
		println!("Verify h1 >= 1 and h1 < N_tilde");
		if statement.h1 <= BigInt::one() || statement.h1 >= statement.N_tilde {
			return Err(DlnProofError::Verify)
		}

		println!("Verify h2 >= 1 and h2 < N_tilde");
		if statement.h2 <= BigInt::one() || statement.h2 >= statement.N_tilde {
			return Err(DlnProofError::Verify)
		}

		println!("Verify h1 != h2");
		if statement.h1 == statement.h2 {
			return Err(DlnProofError::Verify)
		}

		println!("Verify all T_i >= 1 and T_i < N_tilde");
		for t in &self.T {
			let a = t.mod_floor(&statement.N_tilde);
			if a <= BigInt::one() || a >= statement.N_tilde {
				return Err(DlnProofError::Verify)
			}
		}

		println!("Verify all Alpha_i >= 1 and Alpha_i < N_tilde");
		for alpha in &self.Alpha {
			let a = alpha.mod_floor(&statement.N_tilde);
			if a <= BigInt::one() || a >= statement.N_tilde {
				return Err(DlnProofError::Verify)
			}
		}

		// Reconstruct the hash (challenge)
		let mut msg: Vec<&BigInt> = vec![&statement.h1, &statement.h2, &statement.N_tilde];
		for i in 0..ITERATIONS {
			msg.push(&self.Alpha[i]);
		}

		let mut hash = Sha512Trunc256::new();
		for elt in msg.iter() {
			hash = hash.chain_bigint(&elt);
		}
		let c: Vec<_> = hash
			.result_bigint()
			.to_bytes()
			.into_iter()
			.flat_map(|val| {
				[
					(val >> 7) & 1,
					(val >> 6) & 1,
					(val >> 5) & 1,
					(val >> 4) & 1,
					(val >> 3) & 1,
					(val >> 2) & 1,
					(val >> 1) & 1,
					(val >> 0) & 1,
				]
				.into_iter()
			})
			.collect();

		// Validate the zero-knowledge proof
		for i in 0..ITERATIONS {
			let c_i = BigInt::from(c[i] as u16);
			let h1_exp_t_i = BigInt::mod_pow(&statement.h1, &self.T[i], &statement.N_tilde);
			let h2_exp_c_i = BigInt::mod_pow(&statement.h2, &c_i, &statement.N_tilde);
			let alpha_i_mul_h2_exp_c_i =
				BigInt::mod_mul(&self.Alpha[i], &h2_exp_c_i, &statement.N_tilde);

			println!("{:?}", i);
			if h1_exp_t_i != alpha_i_mul_h2_exp_c_i {
				return Err(DlnProofError::Verify)
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utilities::{mta::range_proofs::SampleFromMultiplicativeGroup, BITS_PAILLIER};
	use curv::elliptic::curves::secp256_k1::Secp256k1;
	use paillier::{KeyGeneration, Paillier};
	use sha2::Sha512Trunc256;

	#[test]
	fn test_discrete_log_proof() {
		let statement = DlnProofStatement::generate();
		let x = Scalar::<Secp256k1>::random();
		let witness = DlnProofWitness { x: x.to_bigint() };
		let proof = DlnProof::prove(&witness, &statement);
		let result = proof.verify(&statement);
		assert!(result.is_ok());
	}
}
