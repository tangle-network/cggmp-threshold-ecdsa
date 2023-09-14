#![allow(non_snake_case)]

use curv::{
	arithmetic::traits::*,
	cryptographic_primitives::hashing::{Digest, DigestExt},
	BigInt,
};

use serde::{Deserialize, Serialize};
use sha2::Sha512Trunc256;
use thiserror::Error;

use crate::party_i::Keys;

pub const ITERATIONS: usize = 80;

#[derive(Error, Debug)]
pub enum DlnProofError {
	#[error("dlnproof verification failed")]
	Verify,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DlnProofStatement {
	pub h1: BigInt,
	pub h2: BigInt,
	pub N: BigInt,
}

impl DlnProofStatement {
	/// Generate a discrete logarithm proof statement
	///
	/// Following from https://github.com/bnb-chain/tss-lib/blob/master/ecdsa/keygen/round_1.go#L86-L96
	/// we generate two statements to prove that both h1,h2 generate the same group mod N
	pub fn generate() -> ((Self, DlnProofWitness), (Self, DlnProofWitness)) {
		let key = Keys::create_safe_prime(0);
		(
			(
				DlnProofStatement {
					h1: key.h1.clone(),
					h2: key.h2.clone(),
					N: key.N_tilde.clone(),
				},
				DlnProofWitness { x: key.xhi, p: key.dk.p.clone(), q: key.dk.q.clone() },
			),
			(
				DlnProofStatement { h1: key.h2, h2: key.h1, N: key.N_tilde },
				DlnProofWitness { x: key.xhi_inv, p: key.dk.p, q: key.dk.q },
			),
		)
	}
}

#[derive(Clone)]
pub struct DlnProofWitness {
	pub x: BigInt,
	pub p: BigInt,
	pub q: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlnProof {
	Alpha: Vec<BigInt>,
	T: Vec<BigInt>,
}

impl DlnProof {
	pub fn prove(witness: &DlnProofWitness, statement: &DlnProofStatement) -> Self {
		let p_mul_q = BigInt::mul(&witness.p, &witness.q);
		let mut a: Vec<BigInt> = vec![BigInt::zero(); ITERATIONS];
		let mut alpha: Vec<BigInt> = vec![BigInt::zero(); ITERATIONS];
		for i in 0..ITERATIONS {
			a[i] = BigInt::sample_below(&p_mul_q);
			alpha[i] = BigInt::mod_pow(&statement.h1, &a[i], &statement.N);
		}

		let mut hash = Sha512Trunc256::new()
			.chain_bigint(&statement.h1)
			.chain_bigint(&statement.h2)
			.chain_bigint(&statement.N);
		for i in 0..ITERATIONS {
			hash = hash.chain_bigint(&alpha[i]);
		}

		let digest = hash.result_bigint();
		println!("Prover | Digest: {:?}", digest.to_bytes());

		let c: Vec<_> = digest
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
			let rhs = BigInt::mod_mul(&c_i, &witness.x, &statement.N);
			t[i] = BigInt::mod_add(&a[i], &rhs, &statement.N);

			let h1_exp_t_i = BigInt::mod_pow(&statement.h1, &t[i], &statement.N);
			let h2_exp_c_i = BigInt::mod_pow(&statement.h2, &c_i, &statement.N);
			let alpha_i_mul_h2_exp_c_i = BigInt::mod_mul(&alpha[i], &h2_exp_c_i, &statement.N);
			if h1_exp_t_i != alpha_i_mul_h2_exp_c_i {
				println!("Prover {:?} {:?} | h1_exp_t_i: {:?}", i, c_i, h1_exp_t_i);
				println!(
					"Prover {:?} {:?} | alpha_i_mul_h2_exp_c_i: {:?}",
					i, c_i, alpha_i_mul_h2_exp_c_i
				);
			}
		}

		DlnProof { Alpha: alpha, T: t }
	}

	pub fn verify(&self, statement: &DlnProofStatement) -> Result<(), DlnProofError> {
		let h1 = statement.h1.clone();
		if h1 <= BigInt::one() || h1 >= statement.N {
			return Err(DlnProofError::Verify)
		}

		let h2 = statement.h2.clone();
		if h2 <= BigInt::one() || h2 >= statement.N {
			return Err(DlnProofError::Verify)
		}

		if h1 == h2 {
			return Err(DlnProofError::Verify)
		}

		for t in &self.T {
			let a = t.mod_floor(&statement.N);
			if a <= BigInt::one() || a >= statement.N {
				return Err(DlnProofError::Verify)
			}
		}

		for alpha in &self.Alpha {
			let a = alpha.mod_floor(&statement.N);
			if a <= BigInt::one() || a >= statement.N {
				return Err(DlnProofError::Verify)
			}
		}

		// Reconstruct the hash (challenge)
		let mut hash = Sha512Trunc256::new()
			.chain_bigint(&h1)
			.chain_bigint(&h2)
			.chain_bigint(&statement.N);
		for i in 0..ITERATIONS {
			hash = hash.chain_bigint(&self.Alpha[i]);
		}

		let digest = hash.result_bigint();
		println!("Verifier | Digest: {:?}", digest.to_bytes());

		let c: Vec<_> = digest
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
			let h1_exp_t_i = BigInt::mod_pow(&h1, &self.T[i], &statement.N);
			let h2_exp_c_i = BigInt::mod_pow(&h2, &c_i, &statement.N);
			let alpha_i_mul_h2_exp_c_i = BigInt::mod_mul(&self.Alpha[i], &h2_exp_c_i, &statement.N);

			if h1_exp_t_i != alpha_i_mul_h2_exp_c_i {
				println!("Verifier {:?} {:?} | h1_exp_t_i: {:?}", i, c_i, h1_exp_t_i);
				println!(
					"Verifier {:?} {:?} | alpha_i_mul_h2_exp_c_i: {:?}",
					i, c_i, alpha_i_mul_h2_exp_c_i
				);
				return Err(DlnProofError::Verify)
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_discrete_log_proof() {
		let ((s1, w1), _) = DlnProofStatement::generate();
		let proof = DlnProof::prove(&w1, &s1);
		let result = proof.verify(&s1);
		assert!(result.is_ok());
	}
}
