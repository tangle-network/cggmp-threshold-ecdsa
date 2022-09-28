use crate::keygen::rounds::*;
use fs_dkr::{add_party_message::*, refresh_message::*, error::*};
use round_based::{containers::BroadcastMsgs, Msg};
use crate::party_i::Keys;
use paillier::{EncryptionKey, DecryptionKey};
use crate::party_i::KeyRefreshBroadcastMessageRound1;

pub enum ExistingOrNewParty {
	Existing(LocalKey<Secp256k1>),
	New((JoinMessage, Keys)),
}

pub struct PaillierKeys {
	ek: EncryptionKey,
	dk: DecryptionKey,
}

pub struct Round0 {
	pub local_key_option: Option<LocalKey<Secp256k1>>,
}

impl Round0 {
	pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<Option<JoinMessage>>>,
    {
		match local_key_option {
			Some(local_key) => {
				output.push(Msg{
					sender: local_key.i,
					receiver: None,
					body: None,
				});
				Ok(Round1 {
					party_type: ExistingOrNewParty::Existing(local_key),
				})
			},
			None => {
				let (join_message, paillier_keys) = JoinMessage::distribute();
				output.push(Msg{
					sender: join_message.get_party_index()?,
					receiver: None,
					body: join_message,
				});
				Ok(Round1 {
					party_type: ExistingOrNewParty::New((join_message, paillier_keys)),
				})
			}
		}
    }
    pub fn is_expensive(&self) -> bool {
		true
    }  
}

pub struct Round1 {
	pub party_type: ExistingOrNewParty,
}

impl Round1 {
	pub fn proceed<O>(self, input: BrodcastMsgs<Option<JoinMessage>>, mut output: O) -> Result<Round2>
    where
        O: Push<Msg<Option<KeyRefreshBroadcastMessageRound1>>>,
    {
		let join_message_option_vec = input.into_vec();
		let mut join_message_vec: Vec<JoinMessage> = Vec::new();
		for join_message_option in join_message_option_vec {
			match elem {
				Some(join_message_option) => {
					join_message_vec.push(join_message_option)
				},
				_ => {},
			}
		}
		match party_type {
			ExistingOrNewParty::Existing(local_key) => {
				// Existing parties form a refresh message and broadcast it.
				let join_message_slice = join_message_vec.as_slice();
				output.push(Msg {
					sender: local_key.i,
					receiver: None,
					body: KeyRefreshBroadcastMessageRound1 {
						refresh_message_result: RefreshMessage::replace(join_message_slice, &mut local_key),
					}
				});
				Ok(Round2 {
					party_type: ExistingOrNewParty::Existing(local_key),
					join_messages: join_message_vec,
				})
			}

			ExistingOrNewParty::New((join_message, paillier_keys)) => {
				// New parties don't need to form a refresh message.
				output.push(Msg {
					sender: join_message.get_party_index()?,
					receiver: None,
					body: None,
				});
				Ok(Round2 {
					party_type: ExistingOrNewParty::New((join_message, paillier_keys)),
					join_messages: join_message_vec,
				})
			}
		}
	}

	pub fn is_expensive(&self) -> bool {
		true
    }  
}

pub struct Round2 {
	pub party_type: ExistingOrNewParty,
	pub join_messages: Vec<JoinMessage>,		
}

impl Round2 {

	pub fn is_expensive(&self) -> bool {
		true
    }  
}