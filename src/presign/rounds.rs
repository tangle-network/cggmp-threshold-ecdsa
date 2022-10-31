use std::{char::REPLACEMENT_CHARACTER, collections::HashMap, io::Error, marker::PhantomData};

use super::{PreSigningP2PMessage1, PreSigningP2PMessage2, PreSigningSecrets, SSID};
use curv::{
	arithmetic::Samplable,
	elliptic::curves::{Point, Scalar, Secp256k1},
	BigInt,
};
use fs_dkr::{add_party_message::*, error::*, refresh_message::*};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
	party_i::Keys, state_machine::keygen::*,
};
use paillier::{
	Add, DecryptionKey, Encrypt, EncryptWithChosenRandomness, EncryptionKey, Mul, Paillier,
	Randomness, RawPlaintext,
};
use round_based::{
	containers::{push::Push, BroadcastMsgs, BroadcastMsgsStore, P2PMsgs, P2PMsgsStore},
	Msg,
};
use sha2::Sha256;

use super::state_machine::{Round0Messages, Round1Messages};

pub struct Round0 {
	pub ssid: SSID<Secp256k1>,
	pub secrets: PreSigningSecrets,
	pub l: usize, // This is the number of presignings to run in parallel
}

impl Round0 {
	pub fn proceed<O>(self, mut output: O) -> Result<Round1>
	where
		O: Push<Msg<PreSigningP2PMessage1<Secp256k1>>>,
	{
		let k_i = BigInt::sample_below(&self.ssid.q);
		let gamma_i = BigInt::sample_below(&self.ssid.q);
		let rho_i = crate::utilities::sample_relatively_prime_integer(&self.secrets.ek.n);
		let nu_i = crate::utilities::sample_relatively_prime_integer(&self.secrets.ek.n);
		let G_i = Paillier::encrypt_with_chosen_randomness(
			&self.secrets.ek,
			RawPlaintext::from(gamma_i.clone()),
			&Randomness::from(nu_i.clone()),
		);
		let K_i = Paillier::encrypt_with_chosen_randomness(
			&self.secrets.ek,
			RawPlaintext::from(k_i.clone()),
			&Randomness(rho_i.clone()),
		);
		let witness = crate::utilities::enc::PaillierEncryptionInRangeWitness {
			k: k_i,
			rho: rho_i,
			phantom: std::marker::PhantomData,
		};
		let statement = crate::utilities::enc::PaillierEncryptionInRangeStatement {
			N0: self.secrets.ek.n.clone(),
			NN0: self.secrets.ek.nn.clone(),
			K: K_i,
			s: self.ssid.S.clone(),
			t: self.ssid.T.clone(),
			N_hat: self.ssid.N.clone(),
			phantom: std::marker::PhantomData,
		};
		let psi_j_i =
			crate::utilities::enc::PaillierEncryptionInRangeProof::<Secp256k1, Sha256>::prove(
				&witness, &statement,
			);

		for j in self.ssid.P.iter() {
			if j != &self.ssid.X.i {
				let body = PreSigningP2PMessage1 {
					ssid: self.ssid,
					i: self.ssid.X.i,
					K_i,
					G_i,
					psi_j_i,
					enc_j_statement: statement,
					ek: self.secrets.ek,
				};
				output.push(Msg { sender: self.ssid.X.i, receiver: Some(j.clone()), body });
			}
		}
		Ok(Round1 { ssid: self.ssid, secrets: self.secrets, gamma_i, nu_i })
	}
	pub fn is_expensive(&self) -> bool {
		false
	}
}

pub struct Round1 {
	ssid: SSID<Secp256k1>,
	secrets: PreSigningSecrets,
	gamma_i: BigInt,
	nu_i: BigInt,
}

impl Round1 {
	pub fn proceed<O>(
		self,
		input: P2PMsgs<PreSigningP2PMessage1<Secp256k1>>,
		mut output: O,
	) -> Result<Round2>
	where
		O: Push<Msg<PreSigningP2PMessage1<Secp256k1>>>,
	{
		let K: HashMap<u16, BigInt> = HashMap::new();
		let G: HashMap<u16, BigInt> = HashMap::new();
		let eks: HashMap<u16, EncryptionKey> = HashMap::new();
		// Verify P2P Messages
		for msg in input.into_vec() {
			let j = msg.i;
			K.insert(j, msg.K_i);
			G.insert(j, msg.G_i);
			eks.insert(j, msg.ek);
			let psi_i_j = msg.psi_j_i;
			let enc_i_statement = msg.enc_j_statement.N0;

			crate::utilities::enc::PaillierEncryptionInRangeProof::<Secp256k1, Sha256>::verify(
				&psi_i_j,
				&enc_i_statement,
			);
		}

		// Compute Gamma_i
		let Gamma_i =
			Point::<Secp256k1>::generator().as_point() * Scalar::from_bigint(&self.gamma_i);

		for j in self.ssid.P.iter() {
			if j != &self.ssid.X.i {
				// Sample randomness
				let r_i_j = BigInt::sample_below(eks.get(j).n);
				let s_i_j = BigInt::sample_below(eks.get(j).n);
				let r_hat_i_j = BigInt::sample_below(eks.get(j).n);
				let s_hat_i_j = BigInt::sample_below(eks.get(j).n);

				let upper = BigInt::pow(&BigInt::from(2), crate::utilities::L as u32);
				let lower = BigInt::from(-1).mul(&upper);

				let beta_i_j = BigInt::sample_range(lower, upper);
				let beta_hat_i_j = BigInt::sample_range(lower, upper);

				// Compute D_j_i
				let encrypt_minus_beta_i_j = Paillier::encrypt_with_chosen_randomness(
					&eks.get(j),
					RawPlaintext::from(BigInt::from(-1).mul(beta_i_j)),
					Randomness::from(s_i_j),
				);
				let D_j_i = Paillier::add(
					&eks.get(j),
					Paillier::mul(&eks.get(j), K.get(j), self.gamma_i),
					encrypt_minus_beta_i_j,
				);

				// Compute F_j_i
				let F_j_i = Paillier::encrypt_with_chosen_randomness(
					&self.secrets.ek,
					RawPlaintext::from(beta_i_j),
					Randomness::from(r_i_j),
				);

				// Compute D_hat_j_i
				let encrypt_minus_beta_hat_i_j = Paillier::encrypt_with_chosen_randomness(
					&eks.get(j),
					RawPlaintext::from(BigInt::from(-1).mul(beta_hat_i_j)),
					Randomness::from(s_hat_i_j),
				);
				let D_hat_j_i = Paillier::add(
					&eks.get(j),
					Paillier::mul(&eks.get(j), K.get(j), self.secrets.x_i),
					encrypt_minus_beta_hat_i_j,
				);

				// Compute F_hat_j_i
				let F_hat_j_i = Paillier::encrypt_with_chosen_randomness(
					&self.secrets.ek,
					RawPlaintext::from(beta_hat_i_j),
					Randomness::from(r_hat_i_j),
				);

				// Compute psi_j_i
				let witness_psi_j_i =
					crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeWitness {
						x: self.gamma_i,
						y: beta_i_j,
						rho: s_i_j,
						rho_y: r_i_j,
						phantom: PhantomData,
					};
				let statement_psi_j_i =
					crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeStatement {};
				let psi_j_i = crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeProof::<
					Secp256k1,
					Sha256,
				>::prove(&witness_psi_j_i, &statement_psi_j_i);

				// Compute psi_hat_j_i
				let witness_psi_hat_j_i =
					crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeWitness {
						x: self.secrets.x_i,
						y: beta_hat_i_j,
						rho: s_hat_i_j,
						rho_y: r_hat_i_j,
						phantom: PhantomData,
					};
				let statement_psi_hat_j_i =
					crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeStatement {};
				let psi_hat_j_i = crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeProof::<
					Secp256k1,
					Sha256,
				>::prove(&witness_psi_hat_j_i, &statement_psi_hat_j_i);

				// Compute psi_prime_j_i
				let witness_psi_prime_j_i =
					crate::utilities::log_star::KnowledgeOfExponentPaillierEncryptionWitness {
						x: self.gamma_i,
						rho: self.nu_i,
						phantom: PhantomData,
					};
				let statement_psi_prime_j_i =
					crate::utilities::log_star::KnowledgeOfExponentPaillierEncryptionStatement {};
				let psi_prime_j_i =
					crate::utilities::log_star::KnowledgeOfExponentPaillierEncryptionProof::<
						Secp256k1,
						Sha256,
					>::prove(&witness_psi_j_i, &statement_psi_j_i);

				// Send Message
				let body = PreSigningP2PMessage2 {
					ssid: self.ssid,
					Gamma_i,
					D_j_i,
					F_j_i,
					D_hat_j_i,
					F_hat_j_i,
					psi_j_i,
					psi_hat_j_i,
					psi_prime_j_i,
				};
				output.push(Msg { sender: self.ssid.X.i, receiver: Some(j.clone()), body });
			}
			Ok(Round2 {})
		}
	}

	pub fn is_expensive(&self) -> bool {
		false
	}

	pub fn expects_messages(i: u16, n: u16) -> Round0Messages {
		P2PMsgsStore::new(i, n)
	}
}

pub struct Round2 {}

impl Round2 {
	pub fn proceed(self, input: P2PMsgs<()>) -> Result<Round3> {
		Err()
	}

	pub fn is_expensive(&self) -> bool {
		false
	}
	pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
		P2PMsgsStore::new(i, n)
	}
}

pub struct Round3 {
	t: u16,
	n: u16,
}

impl Round3 {
	pub fn proceed(self, input: P2PMsgs<()>) -> Result<LocalKey<Secp256k1>> {}

	pub fn is_expensive(&self) -> bool {
		false
	}
	pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
		P2PMsgsStore::new(i, n)
	}
}

type Result<T> = std::result::Result<T, Error>;
