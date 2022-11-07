use std::{
	char::REPLACEMENT_CHARACTER, collections::HashMap, f32::consts::E, hash::Hash, io::Error,
	marker::PhantomData,
};

use crate::utilities::{
	aff_g::{
		PaillierAffineOpWithGroupComInRangeProof, PaillierAffineOpWithGroupComInRangeStatement,
		PaillierAffineOpWithGroupComInRangeWitness,
	},
	dec_q::{
		PaillierDecryptionModQProof, PaillierDecryptionModQStatement, PaillierDecryptionModQWitness,
	},
	enc::{
		PaillierEncryptionInRangeProof, PaillierEncryptionInRangeStatement,
		PaillierEncryptionInRangeWitness,
	},
	log_star::{
		KnowledgeOfExponentPaillierEncryptionProof, KnowledgeOfExponentPaillierEncryptionStatement,
		KnowledgeOfExponentPaillierEncryptionWitness,
	},
	mul::{PaillierMulProof, PaillierMulStatement, PaillierMulWitness},
	sample_relatively_prime_integer, L, L_PRIME,
};

use super::{
	IdentifiableAbortBroadcastMessage, PreSigningP2PMessage1, PreSigningP2PMessage2,
	PreSigningP2PMessage3, PreSigningSecrets, PresigningOutput, PresigningTranscript, SSID,
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
	pub S: HashMap<u16, BigInt>,
	pub T: HashMap<u16, BigInt>,
	pub N_hats: HashMap<u16, BigInt>,
	pub l: usize, // This is the number of presignings to run in parallel
}

impl Round0 {
	pub fn proceed<O>(self, mut output: O) -> Result<Round1>
	where
		O: Push<Msg<PreSigningP2PMessage1<Secp256k1>>>,
	{
		// k_i <- F_q
		let k_i = BigInt::sample_below(&self.ssid.q);
		// gamma_i <- F_q
		let gamma_i = BigInt::sample_below(&self.ssid.q);
		// rho_i <- Z*_{N_i}
		let rho_i = sample_relatively_prime_integer(&self.secrets.ek.n);
		// nu_i <- Z*_{N_i}
		let nu_i = sample_relatively_prime_integer(&self.secrets.ek.n);
		// G_i = enc_i(gamma_i; nu_i)
		let G_i: BigInt = Paillier::encrypt_with_chosen_randomness(
			&self.secrets.ek,
			RawPlaintext::from(gamma_i.clone()),
			&Randomness::from(nu_i.clone()),
		)
		.into();
		// K_i = enc_i(k_i; rho_i)
		let K_i: BigInt = Paillier::encrypt_with_chosen_randomness(
			&self.secrets.ek,
			RawPlaintext::from(k_i.clone()),
			&Randomness(rho_i.clone()),
		)
		.into();
		let witness_psi_0_j_i =
			PaillierEncryptionInRangeWitness { k: k_i, rho: rho_i, phantom: PhantomData };

		for j in self.ssid.P.iter() {
			if j != &self.ssid.X.i {
				let statement_psi_0_j_i = PaillierEncryptionInRangeStatement {
					N0: self.secrets.ek.n.clone(),
					NN0: self.secrets.ek.nn.clone(),
					K: K_i,
					s: self.S.get(j),
					t: self.T.get(j),
					N_hat: self.N_hats.get(j),
					phantom: PhantomData,
				};
				let psi_0_j_i = PaillierEncryptionInRangeProof::<Secp256k1, Sha256>::prove(
					&witness_psi_0_j_i,
					&statement_psi_0_j_i,
				);

				let body = PreSigningP2PMessage1 {
					ssid: self.ssid,
					i: self.ssid.X.i,
					K_i,
					G_i,
					psi_0_j_i,
					enc_j_statement: statement_psi_0_j_i,
					ek: self.secrets.ek,
				};
				output.push(Msg { sender: self.ssid.X.i, receiver: Some(j.clone()), body });
			}
		}
		Ok(Round1 {
			ssid: self.ssid,
			secrets: self.secrets,
			gamma_i,
			k_i,
			nu_i,
			rho_i,
			G_i,
			K_i,
			S: self.S,
			T: self.T,
			N_hats: self.N_hats,
		})
	}
	pub fn is_expensive(&self) -> bool {
		false
	}
}

pub struct Round1 {
	pub ssid: SSID<Secp256k1>,
	pub secrets: PreSigningSecrets,
	pub gamma_i: BigInt,
	pub k_i: BigInt,
	pub nu_i: BigInt,
	pub rho_i: BigInt,
	pub G_i: BigInt,
	pub K_i: BigInt,
	pub S: HashMap<u16, BigInt>,
	pub T: HashMap<u16, BigInt>,
	pub N_hats: HashMap<u16, BigInt>,
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
			// j
			let j = msg.i;
			// Insert K_j
			K.insert(j, msg.K_i);
			// Insert G_j
			G.insert(j, msg.G_i);
			// Insert j's Paillier encryption key
			eks.insert(j, msg.ek);
			let psi_0_i_j = msg.psi_0_j_i;
			let enc_i_statement = msg.enc_j_statement;
			// Verify psi_0_i_j proof
			PaillierEncryptionInRangeProof::<Secp256k1, Sha256>::verify(
				&psi_0_i_j,
				&enc_i_statement,
			)
			.map_err(|e| Err(format!("Party {} verification of enc failed", j)));
		}

		// Gamma_i = g^{gamma_i}
		let Gamma_i =
			Point::<Secp256k1>::generator().as_point() * Scalar::from_bigint(&self.gamma_i);
		// {beta, beta_hat, r, r_hat, s, s_hat}_i will store mapping from j to {beta, beta_hat, r,
		// r_hat, s, s_hat}_i_j.
		let beta_i: HashMap<u16, BigInt> = HashMap::new();
		let beta_hat_i: HashMap<u16, BigInt> = HashMap::new();
		let r_i: HashMap<u16, BigInt> = HashMap::new();
		let r_hat_i: HashMap<u16, BigInt> = HashMap::new();
		let s_i: HashMap<u16, BigInt> = HashMap::new();
		let s_hat_i: HashMap<u16, BigInt> = HashMap::new();

		for j in self.ssid.P.iter() {
			if j != &self.ssid.X.i {
				// r_i_j <- Z_{N_j}
				let r_i_j = BigInt::sample_below(eks.get(j).n);
				r_i.insert(j, r_i_j);
				// s_i_j <- Z_{N_j}
				let s_i_j = BigInt::sample_below(eks.get(j).n);
				s_i.insert(j, s_i_j);
				// r_hat_i_j <- Z_{N_j}
				let r_hat_i_j = BigInt::sample_below(eks.get(j).n);
				r_hat_i.insert(j, r_hat_i_j);
				// s_hat_i_j <- Z_{N_j}
				let s_hat_i_j = BigInt::sample_below(eks.get(j).n);
				s_hat_i.insert(j, s_hat_i_j);
				let upper = BigInt::pow(&BigInt::from(2), L_PRIME as u32);
				let lower = BigInt::from(-1).mul(&upper);
				// beta_i_j <- [-2^L_PRIME, 2^L_PRIME]
				let beta_i_j = BigInt::sample_range(lower, upper);
				beta_i.insert(j, beta_i_j);
				// beta_hat_i_j <- [-2^L_PRIME, 2^L_PRIME]
				let beta_hat_i_j = BigInt::sample_range(lower, upper);
				beta_hat_i.insert(j, beta_hat_i_j);

				let encrypt_minus_beta_i_j = Paillier::encrypt_with_chosen_randomness(
					&eks.get(j),
					RawPlaintext::from(BigInt::from(-1).mul(beta_i_j)),
					Randomness::from(s_i_j),
				);
				// D_j_i =  (gamma_i [.] K_j ) ⊕ enc_j(-beta_i_j; s_i_j) where [.] is Paillier
				// multiplication
				let D_j_i = Paillier::add(
					&eks.get(j),
					Paillier::mul(&eks.get(j), K.get(j), self.gamma_i),
					encrypt_minus_beta_i_j,
				);

				// F_j_i = enc_i(beta_i_j, r_i_j)
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
				// D_hat_j_i =  (x_i [.] K_j ) ⊕ enc_j(-beta_hat_i_j; s_hat_i_j) where [.] is
				// Paillier multiplication
				let D_hat_j_i = Paillier::add(
					&eks.get(j),
					Paillier::mul(&eks.get(j), K.get(j), self.secrets.x_i),
					encrypt_minus_beta_hat_i_j,
				);

				// F_hat_j_i = enc_i(beta_hat_i_j, r_hat_i_j)
				let F_hat_j_i = Paillier::encrypt_with_chosen_randomness(
					&self.secrets.ek,
					RawPlaintext::from(beta_hat_i_j),
					Randomness::from(r_hat_i_j),
				);

				// psi_j_i
				let witness_psi_j_i = PaillierAffineOpWithGroupComInRangeWitness {
					x: self.gamma_i,
					y: beta_i_j,
					rho: s_i_j,
					rho_y: r_i_j,
					phantom: PhantomData,
				};
				let statement_psi_j_i = PaillierAffineOpWithGroupComInRangeStatement {
					S: self.S.get(j),
					T: self.T.get(j),
					N_hat: self.N_hats.get(j),
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
				let psi_j_i = PaillierAffineOpWithGroupComInRangeProof::<Secp256k1, Sha256>::prove(
					&witness_psi_j_i,
					&statement_psi_j_i,
				);

				// psi_hat_j_i
				let witness_psi_hat_j_i = PaillierAffineOpWithGroupComInRangeWitness {
					x: self.secrets.x_i,
					y: beta_hat_i_j,
					rho: s_hat_i_j,
					rho_y: r_hat_i_j,
					phantom: PhantomData,
				};
				let statement_psi_hat_j_i = PaillierAffineOpWithGroupComInRangeStatement {
					S: self.S.get(j),
					T: self.T.get(j),
					N_hat: self.N_hats.get(j),
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
				let psi_hat_j_i =
					PaillierAffineOpWithGroupComInRangeProof::<Secp256k1, Sha256>::prove(
						&witness_psi_hat_j_i,
						&statement_psi_hat_j_i,
					);

				// psi_prime_j_i
				let witness_psi_prime_j_i = KnowledgeOfExponentPaillierEncryptionWitness {
					x: self.gamma_i,
					rho: self.nu_i,
					phantom: PhantomData,
				};
				let statement_psi_prime_j_i = KnowledgeOfExponentPaillierEncryptionStatement {
					N0: self.secrets.ek.n,
					NN0: self.secrets.ek.nn,
					C: self.K_i,
					X: Gamma_i,
					s: self.S.get(j),
					t: self.T.get(j),
					N_hat: self.N_hats.get(j),
					phantom: PhantomData,
				};
				let psi_prime_j_i =
					KnowledgeOfExponentPaillierEncryptionProof::<Secp256k1, Sha256>::prove(
						&witness_psi_prime_j_i,
						&statement_psi_prime_j_i,
					);

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
					statement_psi_j_i,
					psi_hat_j_i,
					statement_psi_hat_j_i,
					psi_prime_j_i,
					statement_psi_prime_j_i,
				};
				output.push(Msg { sender: self.ssid.X.i, receiver: Some(j.clone()), body });
			}
			Ok(Round2 {
				ssid: self.ssid,
				secrets: self.secrets,
				gamma_i: self.gamma_i,
				k_i: self.k_i,
				gamma_i: self.gamma_i,
				nu_i: self.nu_i,
				rho_i: self.rho_i,
				G_i: self.G_i,
				K_i: self.K_i,
				beta_i,
				beta_hat_i,
				r_i,
				r_hat_i,
				s_i,
				s_hat_i,
				S: self.S,
				T: self.T,
				N_hats: self.N_hats,
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
	pub ssid: SSID<Secp256k1>,
	pub secrets: PreSigningSecrets,
	pub gamma_i: BigInt,
	pub k_i: BigInt,
	pub nu_i: BigInt,
	pub rho_i: BigInt,
	pub G_i: BigInt,
	pub K_i: BigInt,
	pub beta_i: HashMap<u16, BigInt>,
	pub beta_hat_i: HashMap<u16, BigInt>,
	pub r_i: HashMap<u16, BigInt>,
	pub r_hat_i: HashMap<u16, BigInt>,
	pub s_i: HashMap<u16, BigInt>,
	pub s_hat_i: HashMap<u16, BigInt>,
	pub S: HashMap<u16, BigInt>,
	pub T: HashMap<u16, BigInt>,
	pub N_hats: HashMap<u16, BigInt>,
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
			PaillierAffineOpWithGroupComInRangeProof::<Secp256k1, Sha256>::verify(
				&psi_i_j,
				&statement_psi_i_j,
			)
			.map_err(|e| Err(format!("Party {} verification of aff_j psi failed", j)));

			// Verify second aff-g
			let psi_prime_i_j = msg.psi_prime_j_i;
			let statement_psi_prime_i_j = msg.statement_psi_prime_j_i;
			PaillierAffineOpWithGroupComInRangeProof::<Secp256k1, Sha256>::verify(
				&psi_prime_i_j,
				&statement_psi_prime_i_j,
			)
			.map_err(|e| Err(format!("Party {} verification of aff_j psi prime failed", j)));

			// Verify log*
			let psi_hat_i_j = msg.psi_hat_j_i;
			let statement_psi_hat_i_j = msg.statement_psi_hat_j_i;
			KnowledgeOfExponentPaillierEncryptionProof::<Secp256k1, Sha256>::verify(
				&psi_hat_i_j,
				&statement_psi_hat_i_j,
			)
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
			}
		}

		let sum_of_alphas = alpha_i.values().into_iter().fold(BigInt::zero(), |acc, x| acc.add(x));

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

		for j in self.ssid.P.iter() {
			if j != &self.ssid.X.i {
				// log* proof
				// Compute psi_prime_j_i
				let witness_psi_prime_prime_j_i = KnowledgeOfExponentPaillierEncryptionWitness {
					x: self.k_i,
					rho: self.rho_i,
					phantom: PhantomData,
				};
				let statement_psi_prime_prime_j_i =
					KnowledgeOfExponentPaillierEncryptionStatement {
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
					KnowledgeOfExponentPaillierEncryptionProof::<Secp256k1, Sha256>::prove(
						&witness_psi_prime_prime_j_i,
						&statement_psi_prime_prime_j_i,
					);

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

		Ok(Round3 { ssid: self.ssid, Gamma, k_i: self.k_i, chi_i })
	}

	pub fn is_expensive(&self) -> bool {
		false
	}
	pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
		P2PMsgsStore::new(i, n)
	}
}

pub struct Round3 {
	ssid: SSID<Secp256k1>,
	Gamma: Point<Secp256k1>,
	k_i: BigInt,
	chi_i: BigInt,
}

impl Round3 {
	pub fn proceed<O>(
		self,
		input: P2PMsgs<PreSigningP2PMessage3<Secp256k1>>,
		mut output: O,
	) -> Result<Round4>
	where
		O: Push<Msg<IdentifiableAbortBroadcastMessage<Secp256k1>>>,
	{
		let deltas: HashMap<u16, BigInt> = HashMap::new();
		let Deltas: HashMap<u16, Point<Secp256k1>> = HashMap::new();
		for msg in input.into_vec() {
			let j = msg.i;
			// Verify log star proof
			let psi_prime_prime_i_j = msg.psi_prime_prime_j_i;

			let statement_psi_prime_prime_i_j = msg.statement_psi_prime_prime_j_i;

			KnowledgeOfExponentPaillierEncryptionProof::<Secp256k1, Sha256>::verify(
				&psi_prime_prime_i_j,
				&statement_psi_prime_prime_i_j,
			)
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
			let R = self.Gamma * Scalar::from_bigint(BigInt::mod_inv(&delta));
			let output = PresigningOutput {
				ssid: self.ssid,
				R,
				i: self.ssid.X.i,
				k_i: self.k_i,
				chi_i: self.chi_i,
			};
			let transcript = PresigningTranscript {
				// TODO: fill this in
			};

			let body = IdentifiableAbortBroadcastMessage {
				statements_D_j_i: None,
				D_j_i_proofs: None,
				statement_H_i: None,
				H_i_proof: None,
				statement_delta_i: None,
				delta_i_proof: None,
			};

			output.push(Msg { sender: self.ssid.X.i, receiver: None, body });

			Ok(Round4 { output: Some(output), transcript: Some(transcript) })
		} else {
			// D_j_i proofs
			let D_j_i_proofs: HashMap<u16, PaillierAffineOpWithGroupComInRangeProof<Secp256k1>> =
				HashMap::new();

			let statements_D_j_i: HashMap<
				u16,
				PaillierAffineOpWithGroupComInRangeProof<Secp256k1>,
			> = HashMap::new();

			for j in self.ssid.P.iter() {
				if j != self.ssid.X.i {
					let witness_D_j_i = PaillierAffineOpWithGroupComInRangeWitness {
						x: self.gamma_i,
						y: self.beta_i_j,
						rho: self.s_i_j,
						rho_y: self.r_i_j,
						phantom: PhantomData,
					};
					let statement_D_j_i = PaillierAffineOpWithGroupComInRangeStatement {
						S: self.S.get(j),
						T: self.T.get(j),
						N_hat: self.N_hats.get(j),
						N0: self.secrets.ek.n,
						N1: self.eks.get(j).n,
						NN0: self.secrets.ek.nn,
						NN1: self.eks.get(j).nn,
						C: self.D_j_i,
						D: self.K.get(j),
						Y: self.F_j_i,
						X: self.Gamma_i,
						ek_prover: self.secrets.ek,
						ek_verifier: self.eks.get(j),
						phantom: PhantomData,
					};
					let D_j_i_proof =
						PaillierAffineOpWithGroupComInRangeProof::<Secp256k1, Sha256>::prove(
							&witness_D_j_i,
							&statement_D_j_i,
						);
					D_j_i_proofs.insert(j, D_j_i_proof);
					statements_D_j_i.insert(j, statement_D_j_i);
				}
			}

			// H_i proof
			let H_i_randomness = sample_relatively_prime_integer(&self.secrets.ek.n);
			let H_i = Paillier::encrypt_with_chosen_randomness(
				&self.secrets.ek,
				RawPlaintext::from(BigInt::mul(&self.k_i, &self.gamma_i)),
				Randomness::from(H_i_randomness),
			);
			let witness_H_i = PaillierMulWitness {
				x: self.k_i,
				rho: self.nu_i,
				rho_x: self.nu_i.mul(self.gamma_i),
				phantom: PhantomData,
			};

			let statement_H_i = PaillierMulStatement {
				N: self.secrets.ek.n,
				NN: self.secrets.ek.nn,
				C: self.G_i,
				Y: self.K_i,
				X: H_i,
				ek_prover: self.secrets.ek,
				phantom: PhantomData,
			};

			let H_i_proof =
				PaillierMulProof::<Secp256k1, Sha256>::prove(&witness_H_i, &statement_H_i);

			// delta_i proofs
			let delta_i_encrypted_value = BigInt::one();
			let delta_i_randomness = BigInt::one();
			for j in self.ssid.P.iter() {
				if j != self.ssid.X.i {
					delta_i_encrypted_value.mul(self.D_j_i).mul(self.F_i_j);
					delta_i_randomness.mul(self.rho_i).mul(self.s_j_i).mul(self.r_i_j);
				}
			}
			delta_i_encrypted_value.mul(&H_i);
			delta_i_randomness.mul(H_i_randomness);

			let witness_delta_i = PaillierDecryptionModQWitness {
				y: Paillier::decrypt(&self.secrets.dk, delta_i_encrypted_value),
				rho: H_i_randomness,
				phantom: PhantomData,
			};

			let statement_delta_i = PaillierDecryptionModQStatement {
				S: self.S.get(j),
				T: self.T.get(j),
				N_hat: self.N_hats.get(j),
				N0: self.secrets.ek.n,
				NN0: self.secrets.ek.nn,
				C: delta_i_encrypted_value,
				x: self.delta_i,
				ek_prover: self.secrets.ek,
				phantom: PhantomData,
			};

			let delta_i_proof = PaillierDecryptionModQProof::<Secp256k1, Sha256>::prove(
				&witness_delta_i,
				&statement_delta_i,
			);

			let body = IdentifiableAbortBroadcastMessage {
				statements_D_j_i: Some(statements_D_j_i),
				D_j_i_proofs: Some(D_j_i_proofs),
				statement_H_i: Some(statement_H_i),
				H_i_proof: Some(H_i_proof),
				statement_delta_i: Some(statement_delta_i),
				delta_i_proof: Some(delta_i_proof),
			};

			output.push(Msg { sender: self.ssid.X.i, receiver: None, body });
			Ok(Round4 { output: None, transcript: None })
		}
	}

	pub fn is_expensive(&self) -> bool {
		false
	}
	pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
		P2PMsgsStore::new(i, n)
	}
}

pub struct Round4 {
	output: Option<PresigningOutput<Secp256k1>>,
	transcript: Option<PresigningTranscript<Secp256k1>>,
}

impl Round4 {
	pub fn proceed(
		self,
		input: BroadcastMsgs<IdentifiableAbortBroadcastMessage<Secp256k1>>,
	) -> (Option<PresigningOutput<Secp256k1>>, Option<PresigningTranscript<Secp256k1>>) {
		if self.output.is_some() {
			(self.output, self.transcript)
		} else {
			for msg in input.into_vec() {
				// Check D_i_j proofs
				for i in msg.D_j_i_proofs.keys() {
					let D_i_j_proof = msg.D_j_i_proofs.unwrap().get(i);

					let statement_D_i_j = msg.statements_D_j_i.unwrap().get(i);

					PaillierAffineOpWithGroupComInRangeProof::<Secp256k1, Sha256>::verify(
						&D_i_j_proof,
						&statement_D_i_j,
					)
					.map_err(|e| Err(format!("D_i_j proof failed")));
				}

				// Check H_j proofs
				let H_i_proof = msg.H_i_proof.unwrap();
				let statement_H_i = msg.statement_H_i.unwrap();

				PaillierMulProof::verify(&H_i_proof, &statement_H_i)
					.map_err(|e| Err(format!("H_j proof failed")));

				// Check delta_j_proof
				let delta_i_proof = msg.delta_i_proof.unwrap();
				let statement_delta_i = msg.statement_delta_i.unwrap();

				PaillierDecryptionModQProof::verify(&delta_i_proof, &statement_delta_i)
					.map_err(|e| Err(format!("delta_j proof failed")));
			}
			(None, None)
		}
	}

	pub fn is_expensive(&self) -> bool {
		false
	}
	pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
		P2PMsgsStore::new(i, n)
	}
}

type Result<T> = std::result::Result<T, Error>;
