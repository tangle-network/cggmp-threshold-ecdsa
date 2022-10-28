use std::{collections::HashMap, io::Error};

use curv::{elliptic::curves::Secp256k1, BigInt, arithmetic::Samplable};
use fs_dkr::{add_party_message::*, error::*, refresh_message::*};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
	party_i::Keys, state_machine::keygen::*,
};
use paillier::{DecryptionKey, Paillier, EncryptWithChosenRandomness, RawPlaintext, Randomness};
use round_based::{
	containers::{push::Push, BroadcastMsgs, BroadcastMsgsStore, P2PMsgs, P2PMsgsStore},
	Msg,
};
use sha2::Sha256;
use super::{SSID, PreSigningP2PMessage1, PreSigningSecrets};

use super::state_machine::{Round0Messages, Round1Messages};

pub struct Round0 {
	pub ssid: SSID<Secp256k1>,
	pub secrets: PreSigningSecrets,
	pub l: usize,
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
		let psi_j_i = crate::utilities::enc::PaillierEncryptionInRangeProof::<Secp256k1, Sha256>::prove(
			&witness,
			&statement,
		);
		for j in self.ssid.P.iter() {
			if j != &self.ssid.X.i {
				output.push(Msg {
					sender: self.ssid.X.i,
					receiver: Some(j.clone()),
					body: None
				});
			}
		}
		Ok(())
	}
	pub fn is_expensive(&self) -> bool {
		false
	}
}

pub struct Round1 {
	pub old_to_new_map: HashMap<u16, u16>,
	t: u16,
	n: u16,
}

impl Round1 {
	pub fn proceed<O>(
		self,
		input: BroadcastMsgs<
			Option<JoinMessage<Secp256k1, Sha256, { crate::utilities::STAT_PARAM }>>,
		>,
		mut output: O,
	) -> Result<Round2>
	where
		O: Push<
			Msg<
				Option<
					FsDkrResult<
						RefreshMessage<Secp256k1, Sha256, { crate::utilities::STAT_PARAM }>,
					>,
				>,
			>,
		>,
	{

	}

	pub fn is_expensive(&self) -> bool {
		false
	}

	pub fn expects_messages(i: u16, n: u16) -> Round0Messages {
		P2PMsgsStore::new(i, n)
	}
}

pub struct Round2 {
	t: u16,
	n: u16,
}

impl Round2 {
	pub fn proceed(
		self,
		input: P2PMsgs<()>,
	) -> Result<Round3> {
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
	pub fn proceed(
		self,
		input: P2PMsgs<()>,
	) -> Result<LocalKey<Secp256k1>> {
	}

	pub fn is_expensive(&self) -> bool {
		false
	}
	pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
		P2PMsgsStore::new(i, n)
	}
}

type Result<T> = std::result::Result<T, Error>;
