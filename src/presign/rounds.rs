use std::{
	char::REPLACEMENT_CHARACTER, collections::HashMap, hash::Hash, io::Error, marker::PhantomData,
};

use super::{
	PreSigningP2PMessage1, PreSigningP2PMessage2, PreSigningP2PMessage3, PreSigningSecrets, SSID,
};
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
	Add, Decrypt, DecryptionKey, Encrypt, EncryptWithChosenRandomness, EncryptionKey, Mul,
	Paillier, Randomness, RawCiphertext, RawPlaintext,
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
		let G_i: BigInt = Paillier::encrypt_with_chosen_randomness(
			&self.secrets.ek,
			RawPlaintext::from(gamma_i.clone()),
			&Randomness::from(nu_i.clone()),
		)
		.into();
		let K_i: BigInt = Paillier::encrypt_with_chosen_randomness(
			&self.secrets.ek,
			RawPlaintext::from(k_i.clone()),
			&Randomness(rho_i.clone()),
		)
		.into();
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
		Ok(Round1 { ssid: self.ssid, secrets: self.secrets, gamma_i, nu_i, k_i, rho_i, G_i, K_i })
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
	k_i: BigInt,
	rho_i: BigInt,
	G_i: BigInt,
	K_i: BigInt,
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
		let S: HashMap<u16, BigInt> = HashMap::new();
		let T: HashMap<u16, BigInt> = HashMap::new();
		let N_hats: HashMap<u16, BigInt> = HashMap::new();
		// Verify P2P Messages
		for msg in input.into_vec() {
			let j = msg.i;
			K.insert(j, msg.K_i);
			G.insert(j, msg.G_i);
			eks.insert(j, msg.ek);
			S.insert(j, msg.enc_j_statement.s);
			T.insert(j, msg.enc_j_statement.t);
			N_hats.insert(j, msg.enc_j_statement.N_hat);
			let psi_i_j = msg.psi_j_i;
			let enc_i_statement = msg.enc_j_statement;

			crate::utilities::enc::PaillierEncryptionInRangeProof::<Secp256k1, Sha256>::verify(
				&psi_i_j,
				&enc_i_statement,
			)
			.map_err(|e| Err(format!("Party {} verification of enc failed", j)));
		}

		// Compute Gamma_i
		let Gamma_i =
			Point::<Secp256k1>::generator().as_point() * Scalar::from_bigint(&self.gamma_i);
		let beta_i: HashMap<u32, BigInt> = HashMap::new();
		let beta_hat_i: HashMap<u32, BigInt> = HashMap::new();

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
				beta_i.insert(j, beta_i_j);
				let beta_hat_i_j = BigInt::sample_range(lower, upper);
				beta_hat_i.insert(j, beta_hat_i_j);

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
					crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeStatement {
						S: S.get(j),
						T: T.get(j),
						N_hat: N_hats.get(j),
						N0: self.secrets.ek.n,
						N1: eks.get(j).n,
						NN0: self.secrets.ek.nn,
						NN1: eks.get(j).nn,
						C: D_j_i,
						D: K.get(j),
						Y: F_j_i,
						X: Gamma_i,
						ek_prover: self.secrets.ek,
						ek_verifier: eks.get(j),
						phantom: PhantomData,
					};
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
					crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeStatement {
						S: S.get(j),
						T: T.get(j),
						N_hat: N_hats.get(j),
						N0: self.secrets.ek.n,
						N1: eks.get(j).n,
						NN0: self.secrets.ek.nn,
						NN1: eks.get(j).nn,
						C: D_hat_j_i,
						D: K.get(j),
						Y: F_hat_j_i,
						X: Point::<Secp256k1>::generator().as_point() *
							Scalar::from_bigint(&self.secrets.x_i),
						ek_prover: self.secrets.ek,
						ek_verifier: eks.get(j),
						phantom: PhantomData,
					};
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
					crate::utilities::log_star::KnowledgeOfExponentPaillierEncryptionStatement {
						N0: self.secrets.ek.n,
						NN0: self.secrets.ek.nn,
						C: self.K_i,
						X: Gamma_i,
						s: S.get(j),
						t: T.get(j),
						N_hat: N_hats.get(j),
						phantom: PhantomData,
					};
				let psi_prime_j_i =
					crate::utilities::log_star::KnowledgeOfExponentPaillierEncryptionProof::<
						Secp256k1,
						Sha256,
					>::prove(&witness_psi_prime_j_i, &statement_psi_prime_j_i);

				// Send Message
				let body = PreSigningP2PMessage2 {
					ssid: self.ssid,
					i: self.ssid.X.i,
					Gamma_i,
					D_j_i,
					F_j_i,
					D_hat_j_i,
					F_hat_j_i,
					psi_j_i,
					psi_hat_j_i,
					psi_prime_j_i,
					statement_psi_j_i,
					statement_psi_prime_j_i,
					statement_psi_hat_j_i,
				};
				output.push(Msg { sender: self.ssid.X.i, receiver: Some(j.clone()), body });
			}
			Ok(Round2 {
				ssid: self.ssid,
				secrets: self.secrets,
				gamma_i: self.gamma_i,
				k_i: self.k_i,
				K_i: self.K_i,
				rho_i: self.rho_i,
				beta_i,
				beta_hat_i,
			})
		}
	}

	pub fn is_expensive(&self) -> bool {
		false
	}

	pub fn expects_messages(i: u16, n: u16) -> Round0Messages {
		P2PMsgsStore::new(i, n)
	}
}

pub struct Round2 {
	ssid: SSID<Secp256k1>,
	secrets: PreSigningSecrets,
	gamma_i: BigInt,
	k_i: BigInt,
	K_i: BigInt,
	rho_i: BigInt,
	beta_i: HashMap<u16, BigInt>,
	beta_hat_i: HashMap<u16, BigInt>,
}

impl Round2 {
	pub fn proceed<O>(
		self,
		input: P2PMsgs<PreSigningP2PMessage2<Secp256k1>>,
		mut output: O,
	) -> Result<Round3>
	where
		O: Push<Msg<PreSigningP2PMessage2<Secp256k1>>>,
	{
		let S: HashMap<u16, BigInt> = HashMap::new();
		let T: HashMap<u16, BigInt> = HashMap::new();
		let N_hats: HashMap<u16, BigInt> = HashMap::new();
		let D_i: HashMap<u16, BigInt> = HashMap::new();
		let D_hat_i: HashMap<u16, BigInt> = HashMap::new();
		for msg in input.into_vec() {
			let j = msg.i;
			S.insert(j, msg.statement_psi_j_i.s);
			T.insert(j, msg.psi_j_i.t);
			N_hats.insert(j, msg.psi_j_i.N_hat);
			D_i.insert(j, msg.D_j_i);
			D_hat_i.insert(j, msg.D_hat_j_i);
			// Verify first aff-g
			let psi_i_j = msg.psi_j_i;
			let statement_psi_i_j = msg.statement_psi_j_i;
			crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeProof::<Secp256k1, Sha256>:: verify(
				&psi_i_j,
				&statement_psi_i_j,
			)
			.map_err(|e| Err(format!("Party {} verification of aff_j psi failed", j)));

			// Verify second aff-g
			let psi_prime_i_j = msg.psi_prime_j_i;
			let statement_psi_prime_i_j = msg.statement_psi_prime_j_i;
			crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeProof::<Secp256k1, Sha256>:: verify(
				&psi_prime_i_j,
				&statement_psi_prime_i_j,
			)
			.map_err(|e| Err(format!("Party {} verification of aff_j psi prime failed", j)));

			// Verify log*
			let psi_hat_i_j = msg.psi_hat_j_i;
			let statement_psi_hat_i_j = msg.statement_psi_hat_j_i;
			crate::utilities::log_star::KnowledgeOfExponentPaillierEncryptionProof::<
				Secp256k1,
				Sha256,
			>::verify(&psi_hat_i_j, &statement_psi_hat_i_j)
			.map_err(|e| Err(format!("Party {} verification of log star psi hatfailed", j)));
		}

		// Compute Gamma
		let Gamma = self
			.Gamma_map
			.values()
			.into_iter()
			.fold(Point::<Secp256k1>::zero(), |acc, x| acc.add(x));

		// Compute Delta_i
		let Delta_i = Gamma * Scalar::from_bigint(&self.k_i);

		let alpha_i: HashMap<u16, BigInt> = HashMap::new();
		let alpha_hat_i: HashMap<u16, BigInt> = HashMap::new();
		for j in self.ssid.P.iter() {
			if j != &self.ssid.X.i {
				alpha_i.insert(j, Paillier::decrypt(&self.secrets.ek, D_i.get(j))).into();
				alpha_hat_i
					.insert(j, Paillier::decrypt(&self.secrets.ek, D_hat_i.get(j)))
					.into();

				let sum_of_alphas =
					alpha_i.values().into_iter().fold(BigInt::zero(), |acc, x| acc.add(x));

				let sum_of_alpha_hats =
					alpha_hat_i.values().into_iter().fold(BigInt::zero(), |acc, x| acc.add(x));

				let sum_of_betas =
					self.beta_i.values().into_iter().fold(BigInt::zero(), |acc, x| acc.add(x));

				let sum_of_beta_hats =
					self.beta_hat_i.values().into_iter().fold(BigInt::zero(), |acc, x| acc.add(x));

				let delta_i = BigInt::mod_mul(&self.gamma_i, &self.k_i, self.ssid.q)
					.mod_add(sum_of_alphas, self.ssid.q)
					.add(sum_of_betas, self.ssid.q);

				let chi_i = BigInt::mod_mul(&self.secrets.x_i, &self.k_i, self.ssid.q)
					.mod_add(sum_of_alpha_hats, self.ssid.q)
					.add(sum_of_beta_hats, self.ssid.q);

				// log* proof
				// Compute psi_prime_j_i
				let witness_psi_prime_prime_j_i =
					crate::utilities::log_star::KnowledgeOfExponentPaillierEncryptionWitness {
						x: self.k_i,
						rho: self.rho_i,
						phantom: PhantomData,
					};
				let statement_psi_prime_prime_j_i =
					crate::utilities::log_star::KnowledgeOfExponentPaillierEncryptionStatement {
						N0: self.secrets.ek.n,
						NN0: self.secrets.ek.nn,
						C: self.K_i,
						X: Delta_i,
						s: S.get(j),
						t: T.get(j),
						N_hat: N_hats.get(j),
						phantom: PhantomData,
					};
				let psi_prime_prime_j_i =
					crate::utilities::log_star::KnowledgeOfExponentPaillierEncryptionProof::<
						Secp256k1,
						Sha256,
					>::prove(&witness_psi_prime_prime_j_i, &statement_psi_prime_prime_j_i);

				// Send Message
				let body = PreSigningP2PMessage3 {
					ssid: todo!(),
					i: self.ssid.X.i,
					delta_i,
					Delta_i,
					psi_prime_prime_j_i,
					statement_psi_prime_prime_j_i,
				};
				output.push(Msg { sender: self.ssid.X.i, receiver: Some(j.clone()), body });
			}
		}

		Ok(Round3 {})
	}

	pub fn is_expensive(&self) -> bool {
		false
	}
	pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
		P2PMsgsStore::new(i, n)
	}
}

pub struct Round3 {}

impl Round3 {
	pub fn proceed<O>(
		self,
		input: P2PMsgs<PreSigningP2PMessage3<Secp256k1>>,
		mut output: O,
	) -> Result<Round4>
	where
		O: Push<Msg<PreSigningP2PMessage3<Secp256k1>>>,
	{
		let deltas: HashMap<u16, BigInt> = HashMap::new();
		let Deltas: HashMap<u16, Point<Secp256k1>> = HashMap::new();
		for msg in input.into_vec() {
			let j = msg.i;
			// Verify log star proof
			let psi_prime_prime_i_j = msg.psi_prime_prime_j_i;

			let statement_psi_prime_prime_i_j = msg.statement_psi_prime_prime_j_i;

			crate::utilities::log_star::KnowledgeOfExponentPaillierEncryptionProof::<
				Secp256k1,
				Sha256,
			>::verify(&psi_prime_prime_i_j, &statement_psi_prime_prime_i_j)
			.map_err(|e| {
				Err(format!("Party {} verification of log star psi prime prime failed", j))
			});

			// Add to Deltas and deltas
			deltas.insert(j, msg.delta_i);
			Deltas.insert(j, msg.Delta_i);
		}

		// Compute delta
		let delta = deltas.values().into_iter().fold(BigInt::zero(), |acc, x| acc.add(x));

		// Compute product of Deltas
		let product_of_deltas = Deltas
			.values()
			.into_iter()
			.fold(Point::<Secp256k1>::zero(), |acc, x| acc.add(x));

		if product_of_deltas ==
			Point::<Secp256k1>::generator().as_point() * Scalar::from_bigint(&delta)
		{
		} else {
		}
	}

	pub fn is_expensive(&self) -> bool {
		false
	}
	pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
		P2PMsgsStore::new(i, n)
	}
}

pub struct Round4 {}

impl Round4 {
	pub fn proceed(self, input: P2PMsgs<()>) -> Result<LocalKey<Secp256k1>> {}

	pub fn is_expensive(&self) -> bool {
		false
	}
	pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
		P2PMsgsStore::new(i, n)
	}
}

type Result<T> = std::result::Result<T, Error>;
