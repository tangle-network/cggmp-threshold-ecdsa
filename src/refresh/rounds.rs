use std::collections::HashMap;

use curv::elliptic::curves::Secp256k1;
use fs_dkr::{add_party_message::*, error::*, refresh_message::*};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
	party_i::Keys, state_machine::keygen::*,
};
use paillier::DecryptionKey;
use round_based::{
	containers::{push::Push, BroadcastMsgs, BroadcastMsgsStore},
	Msg,
};

use crate::utilities::sha2::Sha256;

pub enum PartyType {
	Existing(Box<LocalKey<Secp256k1>>),
	New(Box<(JoinMessage<Secp256k1, Sha256, { crate::utilities::STAT_PARAM }>, Keys, u16)>),
}

use super::state_machine::{Round0Messages, Round1Messages};

pub struct Round0 {
	pub local_key_option: Option<LocalKey<Secp256k1>>,
	pub new_party_index_option: Option<u16>,
	pub old_to_new_map: HashMap<u16, u16>,
	pub new_t: u16,
	pub new_n: u16,
	pub current_t: u16,
}

impl Round0 {
	pub fn proceed<O>(self, mut output: O) -> Result<Round1>
	where
		O: Push<Msg<Option<JoinMessage<Secp256k1, Sha256, { crate::utilities::STAT_PARAM }>>>>,
	{
		match self.local_key_option {
			Some(local_key) => {
				output.push(Msg { sender: local_key.i, receiver: None, body: None });
				match self.new_party_index_option {
					None => Ok(Round1 {
						party_type: PartyType::Existing(Box::new(local_key)),
						old_to_new_map: self.old_to_new_map,
						new_t: self.new_t,
						new_n: self.new_n,
						current_t: self.current_t,
					}),
					_ => Err(FsDkrError::NewPartyUnassignedIndexError),
				}
			},
			None => {
				let (mut join_message, paillier_keys) = JoinMessage::distribute();
				match self.new_party_index_option {
					Some(new_party_index) => {
						join_message.set_party_index(new_party_index);
						output.push(Msg {
							sender: join_message.clone().get_party_index()?,
							receiver: None,
							body: Some(join_message.clone()),
						});
						Ok(Round1 {
							party_type: PartyType::New(Box::new((
								join_message.clone(),
								paillier_keys,
								new_party_index,
							))),
							old_to_new_map: self.old_to_new_map,
							new_t: self.new_t,
							new_n: self.new_n,
							current_t: self.current_t,
						})
					},
					None => Err(FsDkrError::NewPartyUnassignedIndexError),
				}
			},
		}
	}
	pub fn is_expensive(&self) -> bool {
		false
	}
}

pub struct Round1 {
	pub party_type: PartyType,
	pub old_to_new_map: HashMap<u16, u16>,
	new_t: u16,
	new_n: u16,
	current_t: u16,
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
				    RefreshMessage<Secp256k1, Sha256, { crate::utilities::STAT_PARAM }>,
				>,
			>,
		>,
	{
		let join_message_option_vec = input.into_vec();
		let mut join_message_vec: Vec<
			JoinMessage<Secp256k1, Sha256, { crate::utilities::STAT_PARAM }>,
		> = Vec::new();
		for join_message_option in join_message_option_vec.into_iter().flatten() {
			join_message_vec.push(join_message_option)
		}
		match self.party_type {
			PartyType::Existing(mut local_key) => {
				// Existing parties form a refresh message and broadcast it.
				let old_i = local_key.i;
				let join_message_slice = join_message_vec.as_slice();
				let refresh_message_result = RefreshMessage::replace(
					join_message_slice,
					&mut local_key,
					&self.old_to_new_map,
					self.new_t,
					self.new_n,
				);
				let refresh_message = refresh_message_result.unwrap();
				let new_paillier_dk = refresh_message.clone().1;
				output.push(Msg {
					sender: old_i,
					receiver: None,
					body: Some(refresh_message.clone().0),
				});
				Ok(Round2 {
					party_type: PartyType::Existing(local_key),
					join_messages: join_message_vec,
					refresh_message: Some(refresh_message.0),
					new_paillier_decryption_key: new_paillier_dk,
					new_t: self.new_t,
					new_n: self.new_n,
					current_t: self.current_t,
				})
			},

			PartyType::New(boxed_new) => {
				let (join_message, paillier_keys, new_party_index) = *boxed_new;
				// New parties don't need to form a refresh message.
				output.push(Msg {
					sender: join_message.get_party_index()?,
					receiver: None,
					body: None,
				});
				Ok(Round2 {
					party_type: PartyType::New(Box::new((
						join_message,
						paillier_keys.clone(),
						new_party_index,
					))),
					join_messages: join_message_vec,
					new_paillier_decryption_key: paillier_keys.dk,
					refresh_message: None,
					new_t: self.new_t,
					new_n: self.new_n,
					current_t: self.current_t,
				})
			},
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
	pub party_type: PartyType,
	pub join_messages: Vec<JoinMessage<Secp256k1, Sha256, { crate::utilities::STAT_PARAM }>>,
	pub refresh_message:
		Option<RefreshMessage<Secp256k1, Sha256, { crate::utilities::STAT_PARAM }>>,
	pub new_paillier_decryption_key: DecryptionKey,
	new_t: u16,
	new_n: u16,
	current_t: u16,
}

impl Round2 {
	pub fn proceed(
		self,
		input: BroadcastMsgs<
			Option<
				RefreshMessage<Secp256k1, Sha256, { crate::utilities::STAT_PARAM }>,
			>,
		>,
	) -> Result<LocalKey<Secp256k1>> {
		let refresh_message_option_vec = input.into_vec_including_me(self.refresh_message);
		let mut refresh_message_vec: Vec<
			RefreshMessage<Secp256k1, Sha256, { crate::utilities::STAT_PARAM }>,
		> = Vec::new();
		for refresh_message_option in refresh_message_option_vec.into_iter().flatten() {
			refresh_message_vec.push(refresh_message_option)
		}

		match self.party_type {
			PartyType::Existing(mut local_key) => {
				let join_message_slice = self.join_messages.as_slice();
				let refresh_message_slice = refresh_message_vec.as_slice();
				RefreshMessage::collect(
					refresh_message_slice,
					&mut local_key,
					self.new_paillier_decryption_key,
					join_message_slice,
					self.current_t,
				)?;
				Ok(*local_key)
			},
			PartyType::New(boxed_new) => {
				let (join_message, paillier_keys, _new_party_index) = *boxed_new;
				let join_message_slice = self.join_messages.as_slice();
				let refresh_message_slice = refresh_message_vec.as_slice();
				JoinMessage::collect(
					&join_message,
					refresh_message_slice,
					paillier_keys,
					join_message_slice,
					self.new_t,
					self.new_n,
					self.current_t,
				)
			},
		}
	}

	pub fn is_expensive(&self) -> bool {
		false
	}
	pub fn expects_messages(i: u16, n: u16) -> Round1Messages {
		BroadcastMsgsStore::new(i, n)
	}
}

type Result<T> = std::result::Result<T, FsDkrError>;
