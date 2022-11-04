use std::{collections::HashMap, marker::PhantomData, ops::Add};

use curv::{
	elliptic::curves::{Point, Scalar, Secp256k1},
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

use super::{SigningBroadcastMessage1, SigningIdentifiableAbortMessage, SigningOutput, SSID};

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
		if self.presigning_data.get(self.l).is_some() {
			let (output, transcript) = self.presigning_data.get(self.l).unwrap();
			let r = output.R.x_coord().unwrap();
			let sigma_i = output.k_i.mul(self.m).add(r.mul(output.chi_i));
			let body = SigningBroadcastMessage1 { ssid: self.ssid, i: self.ssid.X.i, sigma_i };
			output.push(Msg { sender: self.ssid.X.i, receiver: None, body });
			// TODO: Erase output from memory
			Ok(Round1 {
				ssid: self.ssid,
				i: self.ssid.X.i,
				r,
				m: self.m,
				presigning_transcript: transcript,
				sigma: sigma_i,
			})
		} else {
			Err(format!("No offline stage for {}", self.l))
		}
	}
	pub fn is_expensive(&self) -> bool {
		false
	}
}

pub struct Round1 {
	pub ssid: SSID<Secp256k1>,
	pub i: u16,
	pub r: BigInt,
	pub m: BigInt,
	pub presigning_transcript: PresigningTranscript<Secp256k1>,
	pub sigma: BigInt,
}

impl Round1 {
	pub fn proceed<O>(
		self,
		input: BroadcastMsgs<SigningBroadcastMessage1<Secp256k1>>,
		mut output: O,
	) -> Result<Round2>
	where
		O: Push<Msg<SigningIdentifiableAbortMessage<Secp256k1>>>,
	{
		let sigmas: HashMap<u16, BigInt> = HashMap::new();
		sigmas.insert(self.i, self.sigma);
		for msg in input.into_vec() {
			sigmas.insert(msg.i, msg.sigma_i);
		}
		let sigma: BigInt = sigmas.values().into_iter().fold(BigInt::zero(), |acc, x| acc.add(x));

		// Verify (r, sigma) is a valid signature
		let sigma_inv = BigInt::mod_inv(sigma);
		let m_sigma_inv = self.m.mul(sigma_inv);
		let r_sigma_inv = self.r.mul(sigma_inv);
		let g = Point::<Secp256k1>::generator();
		let X = self.ssid.X.public_key();
		let x_projection = (g * Scalar::from_bigint(m_sigma_inv))
			.add(X * Scalar::from_bigint(r_sigma_inv))
			.x_coord();

		if self.r == x_projection {
			let signing_output = SigningOutput { ssid: self.ssid, m: self.m, r: self.r, sigma };
			output.push(Msg { sender: self.ssid.X.i, receiver: None, body: None });
			Ok(Round2 { output: Some(signing_output) })
		} else {
			// aff-g proofs
			let D_hat_j_i_proofs: HashMap<
				u16,
				PaillierAffineOpWithGroupComInRangeProof<Secp256k1>,
			> = HashMap::new();
			let statements_D_hat_j_i: HashMap<
				u16,
				PaillierAffineOpWithGroupComInRangeStatement<Secp256k1>,
			> = HashMap::new();

			for j in self.ssid.P.iter() {
				if j != self.ssid.X.i {
					let witness_D_hat_j_i =
						crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeWitness {
							x: todo!(),
							y: todo!(),
							rho: todo!(),
							rho_y: todo!(),
							phantom: PhantomData,
						};
					let statement_D_hat_j_i =
						crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeStatement {
							S: todo!(),
							T: todo!(),
							N_hat: todo!(),
							N0: todo!(),
							N1: todo!(),
							NN0: todo!(),
							NN1: todo!(),
							C: todo!(),
							D: todo!(),
							Y: todo!(),
							X: todo!(),
							ek_prover: todo!(),
							ek_verifier: todo!(),
							phantom: PhantomData,
						};
					let D_hat_j_i_proof =
						crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeProof::<
							Secp256k1,
							Sha256,
						>::prove(&witness_D_hat_j_i, &statement_D_hat_j_i);
					D_hat_j_i_proofs.insert(j, D_hat_j_i_proof);
					statements_D_hat_j_i.insert(j, statement_D_hat_j_i);
				}
			}

			// mul* proof
			let H_hat_i_randomness = crate::utilities::sample_relatively_prime_integer(
				&self.presigning_transcript.secrets.ek.n,
			);
			let H_hat_i = Paillier::encrypt_with_chosen_randomness(
				&self.presigning_transcript.ek,
				RawPlaintext::from(
					self.presigning_transcript.k_i.mul(self.presigning_transcript.x_i),
				),
				Randomness::from(H_hat_i_randomness),
			);
			let witness_H_hat_i = PaillierMultiplicationVersusGroupWitness {
				x: self.presigning_transcript.x_i,
				rho: self.presigning_transcript.rho_i.mul(&H_hat_i_randomness),
				phantom: PhantomData,
			};

			let statement_H_hat_i = PaillierMultiplicationVersusGroupStatement {
				N0: self.presigning_transcript.secrets.ek.n,
				NN0: self.presigning_transcript.secrets.ek.nn,
				C: self.presigning_transcript.K_i,
				D: self.presigning_transcript.H_hat_i,
				X: self.presigning_transcript.X_i,
				N_hat: self.presigning_transcript.N_hats.get(j),
				s: self.presigning_transcript.S_hats.get(j),
				t: self.presigning_transcript.T_hats.get(j),
				phantom: PhantomData,
			};

			let H_hat_i_proof = PaillierMultiplicationVersusGroupProof::<Secp256k1, Sha256>::prove(
				&witness_H_hat_i,
				&statement_H_hat_i,
			);

			// dec proof
			let witness_sigma_i =
				PaillierDecryptionModQWitness { y: todo!(), rho: todo!(), phantom: PhantomData };

			let statement_sigma_i = PaillierDecryptionModQStatement {
				S: todo!(),
				T: todo!(),
				N_hat: todo!(),
				N0: todo!(),
				NN0: todo!(),
				C: todo!(),
				x: todo!(),
				ek_prover: todo!(),
				phantom: PhantomData,
			};

			let sigma_i_proof = PaillierDecryptionModQProof::<Secp256k1, Sha256>::prove(
				&witness_sigma_i,
				&statement_sigma_i,
			);

			let body = SigningIdentifiableAbortMessage {
				D_hat_j_i_proofs,
				statements_D_hat_j_i,
				H_hat_i_proof,
				statement_H_hat_i,
				sigma_i_proof,
				statement_sigma_i,
			};
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
		input: BroadcastMsgs<SigningIdentifiableAbortMessage<Secp256k1>>,
	) -> Option<SigningOutput<Secp256k1>> {
		if self.output.is_some() {
			(self.output, self.transcript)
		} else {
			for msg in input.into_vec() {
				// Check D_i_j proofs
				for i in msg.D_hat_j_i_proofs.keys() {
					let D_hat_i_j_proof = msg.D_hat_j_i_proofs.unwrap().get(i);

					let statement_D_i_j = msg.statements_D_hat_j_i.unwrap().get(i);

					crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeProof::<
						Secp256k1,
						Sha256,
					>::verify(&D_hat_i_j_proof, &statement_D_i_j)
					.map_err(|e| Err(format!("D_hat_i_j proof failed")));
				}

				// Check H_j proofs
				let H_hat_i_proof = msg.H_hat_i_proof.unwrap();
				let statement_H_hat_i = msg.statement_H_hat_i.unwrap();

				PaillierMultiplicationVersusGroupProof::verify(&H_hat_i_proof, &statement_H_hat_i)
					.map_err(|e| Err(format!("H_hat_j proof failed")));

				// Check delta_j_proof
				let sigma_i_proof = msg.sigma_i_proof.unwrap();
				let statement_sigma_i = msg.statement_sigma_i.unwrap();

				PaillierDecryptionModQProof::verify(&sigma_i_proof, &statement_sigma_i)
					.map_err(|e| Err(format!("sigma_j proof failed")));
			}
			None
		}
	}

	pub fn is_expensive(&self) -> bool {
		false
	}
	pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
		BroadcastMsgsStore::new(i, n)
	}
}

type Result<T> = std::result::Result<T, Error>;
