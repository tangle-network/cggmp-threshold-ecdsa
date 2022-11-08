use std::{collections::HashMap, io::Error, marker::PhantomData};

use curv::{
	arithmetic::{traits::*, Modulo, Samplable},
	cryptographic_primitives::hashing::{Digest, DigestExt},
	elliptic::curves::{Curve, Point, Scalar, Secp256k1},
	BigInt,
};
use round_based::{
	containers::{push::Push, BroadcastMsgs, BroadcastMsgsStore},
	Msg,
};
use sha2::Sha256;

use paillier::*;

use crate::{
	presign::{PresigningOutput, PresigningTranscript},
	utilities::{
		aff_g::{
			PaillierAffineOpWithGroupComInRangeProof, PaillierAffineOpWithGroupComInRangeStatement,
		},
		dec_q::{
			PaillierDecryptionModQProof, PaillierDecryptionModQStatement,
			PaillierDecryptionModQWitness,
		},
		mul_star::{
			PaillierMultiplicationVersusGroupProof, PaillierMultiplicationVersusGroupStatement,
			PaillierMultiplicationVersusGroupWitness,
		},
	},
};
use thiserror::Error;

use zeroize::Zeroize;

use super::{SigningBroadcastMessage1, SigningIdentifiableAbortMessage, SigningOutput, SSID};

use super::state_machine::{Round0Messages, Round1Messages};

pub struct Round0 {
	pub ssid: SSID<Secp256k1>,
	pub l: usize, // This is the number of presignings to run in parallel
	pub m: BigInt,
	pub presigning_data:
		HashMap<u16, (PresigningOutput<Secp256k1>, PresigningTranscript<Secp256k1>)>,
}

impl Round0 {
	pub fn proceed<O>(self, mut output: O) -> Result<Round1>
	where
		O: Push<Msg<SigningBroadcastMessage1<Secp256k1>>>,
	{
		// If there is a record for (l,...)
		if let Some((presigning_output, presigning_transcript)) =
			self.presigning_data.get(&(self.l as u16))
		{
			// r = R projected onto x axis
			let r = presigning_output.R.x_coord().unwrap();
			// sigma_i = k*m + r*chi
			let sigma_i = presigning_output.k_i.mul(&self.m).add(&r.mul(&presigning_output.chi_i));
			let body = SigningBroadcastMessage1 { ssid: self.ssid, i: self.ssid.X.i, sigma_i };
			output.push(Msg { sender: self.ssid.X.i, receiver: None, body });
			// Erase output from memory
			(*presigning_output).zeroize();
			Ok(Round1 {
				ssid: self.ssid,
				i: self.ssid.X.i,
				presigning_transcript: presigning_transcript.clone(),
				m: self.m,
				r,
				sigma_i,
			})
		} else {
			Err(SignError::NoOfflineStageError)
		}
	}
	pub fn is_expensive(&self) -> bool {
		false
	}
}

pub struct Round1 {
	pub ssid: SSID<Secp256k1>,
	pub i: u16,
	pub m: BigInt,
	pub r: BigInt,
	pub sigma_i: BigInt,
	pub presigning_transcript: PresigningTranscript<Secp256k1>,
}

impl Round1 {
	pub fn proceed<O>(
		self,
		input: BroadcastMsgs<SigningBroadcastMessage1<Secp256k1>>,
		mut output: O,
	) -> Result<Round2>
	where
		O: Push<Msg<Option<SigningIdentifiableAbortMessage<Secp256k1>>>>,
	{
		// Mapping from j to sigma_j
		let sigmas: HashMap<u16, BigInt> = HashMap::new();
		for msg in input.into_vec() {
			sigmas.insert(msg.i, msg.sigma_i);
		}
		let sigma: BigInt = sigmas.values().into_iter().fold(self.sigma_i, |acc, x| acc.add(x));

		// Verify (r, sigma) is a valid signature
		// sigma^{-1}
		let sigma_inv = BigInt::mod_inv(&sigma, &self.ssid.q).unwrap();
		// m*sigma^{-1}
		let m_sigma_inv = self.m.mul(&sigma_inv);
		// r*sigma^{-1}
		let r_sigma_inv = self.r.mul(&sigma_inv);
		let g = Point::<Secp256k1>::generator();
		let X = self.ssid.X.public_key();
		let x_projection = ((g * Scalar::from_bigint(&m_sigma_inv)) +
			(X * Scalar::from_bigint(&r_sigma_inv)))
		.x_coord()
		.unwrap();

		if self.r == x_projection {
			let signing_output = SigningOutput { ssid: self.ssid, m: self.m, r: self.r, sigma };
			output.push(Msg { sender: self.ssid.X.i, receiver: None, body: None });
			Ok(Round2 { output: Some(signing_output) })
		} else {
			// D_hat_j_i proofs
			let proofs_D_hat_j_i: HashMap<
				u16,
				PaillierAffineOpWithGroupComInRangeProof<Secp256k1, Sha256>,
			> = HashMap::new();
			// D_hat_j_i statements
			let statements_D_hat_j_i: HashMap<
				u16,
				PaillierAffineOpWithGroupComInRangeStatement<Secp256k1, Sha256>,
			> = HashMap::new();

			for j in self.ssid.P.iter() {
				if *j != self.ssid.X.i {
					// Compute D_hat_j_i
					let encrypt_minus_beta_hat_i_j = Paillier::encrypt_with_chosen_randomness(
						self.presigning_transcript.eks.get(j).unwrap(),
						RawPlaintext::from(
							BigInt::from(-1)
								.mul(self.presigning_transcript.beta_hat_i.get(j).unwrap()),
						),
						&Randomness::from(self.presigning_transcript.s_hat_i.get(j).unwrap()),
					);
					// D_hat_j_i =  (x_i [.] K_j ) ⊕ enc_j(-beta_hat_i_j; s_hat_i_j) where [.] is
					// Paillier multiplication
					let D_hat_j_i = Paillier::add(
						self.presigning_transcript.eks.get(j).unwrap(),
						Paillier::mul(
							self.presigning_transcript.eks.get(j).unwrap(),
							RawCiphertext::from(self.presigning_transcript.K.get(j).unwrap()),
							RawPlaintext::from(self.presigning_transcript.secrets.x_i),
						),
						RawCiphertext::from(encrypt_minus_beta_hat_i_j),
					)
					.into();

					// F_hat_j_i = enc_i(beta_hat_i_j, r_hat_i_j)
					let F_hat_j_i = Paillier::encrypt_with_chosen_randomness(
						&self.presigning_transcript.secrets.ek,
						RawPlaintext::from(self.presigning_transcript.beta_hat_i.get(j).unwrap()),
						&Randomness::from(self.presigning_transcript.r_hat_i.get(j).unwrap()),
					)
					.into();

					let witness_D_hat_j_i =
						crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeWitness {
							x: self.presigning_transcript.secrets.x_i,
							y: self.presigning_transcript.beta_hat_i.get(j).unwrap().clone(),
							rho: self.presigning_transcript.s_hat_i.get(j).unwrap().clone(),
							rho_y: self.presigning_transcript.r_hat_i.get(j).unwrap().clone(),
							phantom: PhantomData,
						};
					let statement_D_hat_j_i =
						crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeStatement {
							S: self.presigning_transcript.S.get(j).unwrap().clone(),
							T: self.presigning_transcript.T.get(j).unwrap().clone(),
							N_hat: self.presigning_transcript.N_hats.get(j).unwrap().clone(),
							N0: self.presigning_transcript.secrets.ek.n,
							N1: self.presigning_transcript.eks.get(j).unwrap().clone().n,
							NN0: self.presigning_transcript.secrets.ek.nn,
							NN1: self.presigning_transcript.eks.get(j).unwrap().clone().nn,
							C: D_hat_j_i,
							D: self.presigning_transcript.K.get(j).unwrap().clone(),
							Y: F_hat_j_i,
							X: Point::<Secp256k1>::generator().as_point() *
								Scalar::from_bigint(&self.presigning_transcript.secrets.x_i),
							ek_prover: self.presigning_transcript.secrets.ek,
							ek_verifier: self.presigning_transcript.eks.get(j).unwrap().clone(),
							phantom: PhantomData,
						};
					let proof_D_hat_j_i =
						crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeProof::<
							Secp256k1,
							Sha256,
						>::prove(&witness_D_hat_j_i, &statement_D_hat_j_i);
					proofs_D_hat_j_i.insert(*j, proof_D_hat_j_i);
					statements_D_hat_j_i.insert(*j, statement_D_hat_j_i);
				}
			}

			// mul* proof
			let H_hat_i_randomness = crate::utilities::sample_relatively_prime_integer(
				&self.presigning_transcript.secrets.ek.n,
			);
			let H_hat_i = Paillier::encrypt_with_chosen_randomness(
				&self.presigning_transcript.secrets.ek,
				RawPlaintext::from(
					self.presigning_transcript.k_i.mul(&self.presigning_transcript.secrets.x_i),
				),
				&Randomness::from(H_hat_i_randomness),
			)
			.into();
			let witness_H_hat_i = PaillierMultiplicationVersusGroupWitness {
				x: self.presigning_transcript.secrets.x_i,
				rho: self.presigning_transcript.rho_i.mul(&H_hat_i_randomness),
				phantom: PhantomData,
			};

			let X_i = Point::<Secp256k1>::generator() *
				Scalar::from_bigint(&self.presigning_transcript.secrets.x_i);
			let statement_H_hat_i = PaillierMultiplicationVersusGroupStatement {
				N0: self.presigning_transcript.secrets.ek.n,
				NN0: self.presigning_transcript.secrets.ek.nn,
				C: self.presigning_transcript.K_i,
				D: H_hat_i,
				X: X_i,
				N_hat: self.presigning_transcript.N_hats.get(j).unwrap().clone(),
				s: self.presigning_transcript.S.get(j).unwrap().clone(),
				t: self.presigning_transcript.T.get(j).unwrap().clone(),
				phantom: PhantomData,
			};

			let H_hat_i_proof = PaillierMultiplicationVersusGroupProof::<Secp256k1, Sha256>::prove(
				&witness_H_hat_i,
				&statement_H_hat_i,
			);

			// dec proof
			let ciphertext = H_hat_i;
			let ciphertext_randomness = H_hat_i_randomness;
			for j in self.ssid.P.iter() {
				if *j != self.i {
					ciphertext
						.mul(&self.presigning_transcript.D_hat_i.get(j).unwrap())
						.mul(&F_hat_j_i);
					ciphertext_randomness
						.mul(&s_hat_j_i)
						.mul(&self.presigning_transcript.r_hat_i.get(j).unwrap());
				}
			}

			ciphertext.pow(&self.r);
			ciphertext.mul(&self.presigning_transcript.K_i.pow(&self.m));
			ciphertext_randomness
				.pow(&self.r)
				.mul(&self.presigning_transcript.k_i.pow(&self.m));

			let witness_sigma_i = PaillierDecryptionModQWitness {
				y: Paillier::decrypt(
					&self.presigning_transcript.secrets.dk,
					RawCiphertext::from(ciphertext),
				)
				.into(),
				rho: ciphertext_randomness,
				phantom: PhantomData,
			};

			let statement_sigma_i = PaillierDecryptionModQStatement {
				S: self.presigning_transcript.S.get(j).unwrap().clone(),
				T: self.presigning_transcript.T.get(j).unwrap().clone(),
				N_hat: self.presigning_transcript.N_hats.get(j).unwrap().clone(),
				N0: self.presigning_transcript.secrets.ek.n,
				NN0: self.presigning_transcript.secrets.ek.nn,
				C: ciphertext,
				x: self.sigma_i,
				ek_prover: self.presigning_transcript.secrets.ek,
				phantom: PhantomData,
			};

			let sigma_i_proof = PaillierDecryptionModQProof::<Secp256k1, Sha256>::prove(
				&witness_sigma_i,
				&statement_sigma_i,
			);

			let body = Some(SigningIdentifiableAbortMessage {
				proofs_D_hat_j_i,
				statements_D_hat_j_i,
				H_hat_i_proof,
				statement_H_hat_i,
				sigma_i_proof,
				statement_sigma_i,
			});
			output.push(Msg { sender: self.ssid.X.i, receiver: None, body });
			Ok(Round2 { output: None })
		}
	}

	pub fn is_expensive(&self) -> bool {
		false
	}

	pub fn expects_messages(i: u16, n: u16) -> Round0Messages {
		BroadcastMsgsStore::new(i, n)
	}
}

pub struct Round2 {
	output: Option<SigningOutput<Secp256k1>>,
}

impl Round2 {
	pub fn proceed(
		self,
		input: BroadcastMsgs<Option<SigningIdentifiableAbortMessage<Secp256k1>>>,
	) -> Result<Option<SigningOutput<Secp256k1>>> {
		if self.output.is_some() {
			Ok(Some(self.output.unwrap()))
		} else {
			for msg in input.into_vec() {
				let msg = msg.unwrap();
				// Check D_i_j proofs
				for i in msg.proofs_D_hat_j_i.keys() {
					let D_hat_i_j_proof = msg.proofs_D_hat_j_i.get(i).unwrap();

					let statement_D_i_j = msg.statements_D_hat_j_i.get(i).unwrap();

					if PaillierAffineOpWithGroupComInRangeProof::<Secp256k1, Sha256>::verify(
						D_hat_i_j_proof,
						statement_D_i_j,
					)
					.is_err()
					{
						return Err(SignError::ProofVerificationError)
					}
				}

				// Check H_j proofs
				let H_hat_i_proof = msg.H_hat_i_proof;
				let statement_H_hat_i = msg.statement_H_hat_i;

				if PaillierMultiplicationVersusGroupProof::verify(
					&H_hat_i_proof,
					&statement_H_hat_i,
				)
				.is_err()
				{
					return Err(SignError::ProofVerificationError)
				}

				// Check delta_j_proof
				let sigma_i_proof = msg.sigma_i_proof;
				let statement_sigma_i = msg.statement_sigma_i;

				if PaillierDecryptionModQProof::verify(&sigma_i_proof, &statement_sigma_i).is_err()
				{
					return Err(SignError::ProofVerificationError)
				}
			}
			Ok(None)
		}
	}

	pub fn is_expensive(&self) -> bool {
		false
	}
	pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
		BroadcastMsgsStore::new(i, n)
	}
}

type Result<T> = std::result::Result<T, SignError>;

#[derive(Error, Debug, Clone)]
pub enum SignError {
	#[error("Proof Verification Error")]
	ProofVerificationError,

	#[error("Offline Stage Does Not Exist")]
	NoOfflineStageError,
}
