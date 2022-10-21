use curv::elliptic::curves::Secp256k1;
use fs_dkr::{add_party_message::*, error::*, refresh_message::*};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
	party_i::Keys, state_machine::keygen::*,
};
use paillier::DecryptionKey;
use round_based::{
	containers::{push::Push, BroadcastMsgs, BroadcastMsgsStore, Store},
	Msg,
};
use sha2::Sha256;

pub enum ExistingOrNewParty {
	Existing(LocalKey<Secp256k1>),
	New((JoinMessage, Keys, u16)),
}

pub struct Round0 {
	pub local_key_option: Option<LocalKey<Secp256k1>>,
	pub new_party_index_option: Option<u16>,
	pub t: u16,
	pub n: u16,
}

impl Round0 {
	pub fn proceed<O>(self, mut output: O) -> Result<Round1>
	where
		O: Push<Msg<Option<JoinMessage>>>,
	{
		match self.local_key_option {
			Some(local_key) => {
				output.push(Msg { sender: local_key.i, receiver: None, body: None });
				match self.new_party_index_option {
					None => Ok(Round1 {
						party_type: ExistingOrNewParty::Existing(local_key),
						t: self.t,
						n: self.n,
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
							sender: join_message.clone().get_party_index()?.try_into().unwrap(),
							receiver: None,
							body: Some(join_message.clone()),
						});
						Ok(Round1 {
							party_type: ExistingOrNewParty::New((
								join_message.clone(),
								paillier_keys,
								new_party_index,
							)),
							t: self.t,
							n: self.n,
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
	pub party_type: ExistingOrNewParty,
	t: u16,
	n: u16,
}

impl Round1 {
	pub fn proceed<O>(
		self,
		input: BroadcastMsgs<Option<JoinMessage>>,
		mut output: O,
	) -> Result<Round2>
	where
		O: Push<Msg<Option<FsDkrResult<RefreshMessage<Secp256k1, Sha256>>>>>,
	{
		let join_message_option_vec = input.into_vec();
		let mut join_message_vec: Vec<JoinMessage> = Vec::new();
		for join_message_option in join_message_option_vec {
			match join_message_option {
				Some(join_message_option) => join_message_vec.push(join_message_option),
				_ => {},
			}
		}
		match self.party_type {
			ExistingOrNewParty::Existing(mut local_key) => {
				// Existing parties form a refresh message and broadcast it.
				let join_message_slice = join_message_vec.as_slice();
				let refresh_message_result =
					RefreshMessage::replace(join_message_slice, &mut local_key, self.n);
				let refresh_message = refresh_message_result.unwrap();
				let new_paillier_dk = refresh_message.clone().1;
				let _new_local_key = local_key.clone();
				output.push(Msg {
					sender: local_key.i,
					receiver: None,
					body: Some(Ok(refresh_message.clone().0)),
				});
				Ok(Round2 {
					party_type: ExistingOrNewParty::Existing(local_key),
					join_messages: join_message_vec,
					refresh_message: Some(Ok(refresh_message.0)),
					new_paillier_decryption_key: new_paillier_dk,
					t: self.t,
					n: self.n,
				})
			},

			ExistingOrNewParty::New((join_message, paillier_keys, new_party_index)) => {
				// New parties don't need to form a refresh message.
				output.push(Msg {
					sender: join_message.get_party_index()?.try_into().unwrap(),
					receiver: None,
					body: None,
				});
				Ok(Round2 {
					party_type: ExistingOrNewParty::New((
						join_message,
						paillier_keys.clone(),
						new_party_index,
					)),
					join_messages: join_message_vec,
					new_paillier_decryption_key: paillier_keys.dk,
					refresh_message: None,
					t: self.t,
					n: self.n,
				})
			},
		}
	}

	pub fn is_expensive(&self) -> bool {
		false
	}

	pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<Option<JoinMessage>>> {
		BroadcastMsgsStore::new(i, n)
	}
}

pub struct Round2 {
	pub party_type: ExistingOrNewParty,
	pub join_messages: Vec<JoinMessage>,
	pub refresh_message: Option<FsDkrResult<RefreshMessage<Secp256k1, Sha256>>>,
	pub new_paillier_decryption_key: DecryptionKey,
	t: u16,
	n: u16,
}

impl Round2 {
	pub fn proceed(
		self,
		input: BroadcastMsgs<Option<FsDkrResult<RefreshMessage<Secp256k1, Sha256>>>>,
	) -> Result<LocalKey<Secp256k1>> {
		let refresh_message_option_vec = input.into_vec_including_me(self.refresh_message);
		let mut refresh_message_vec: Vec<RefreshMessage<Secp256k1, Sha256>> = Vec::new();
		for refresh_message_option in refresh_message_option_vec {
			match refresh_message_option {
				Some(refresh_message_option) =>
					refresh_message_vec.push(refresh_message_option.unwrap()),
				_ => {},
			}
		}

		match self.party_type {
			ExistingOrNewParty::Existing(mut local_key) => {
				let join_message_slice = self.join_messages.as_slice();
				let refresh_message_slice = refresh_message_vec.as_slice();
				RefreshMessage::collect(
					refresh_message_slice,
					&mut local_key,
					self.new_paillier_decryption_key,
					join_message_slice,
				)?;
				Ok(local_key)
			},
			ExistingOrNewParty::New((join_message, paillier_keys, _new_party_index)) => {
				let join_message_slice = self.join_messages.as_slice();
				let refresh_message_slice = refresh_message_vec.as_slice();
				JoinMessage::collect(
					&join_message,
					refresh_message_slice,
					paillier_keys,
					join_message_slice,
					self.t.try_into().unwrap(),
					self.n.try_into().unwrap(),
				)
			},
		}
	}

	pub fn is_expensive(&self) -> bool {
		false
	}
	pub fn expects_messages(
		i: u16,
		n: u16,
	) -> Store<BroadcastMsgs<Option<FsDkrResult<RefreshMessage<Secp256k1, Sha256>>>>> {
		BroadcastMsgsStore::new(i, n)
	}
}

type Result<T> = std::result::Result<T, FsDkrError>;
