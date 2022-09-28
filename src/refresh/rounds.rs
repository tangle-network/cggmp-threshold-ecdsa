use crate::keygen::rounds::*;
use fs_dkr::{add_party_message::*, refresh_message::*};
use round_based::{containers::BroadcastMsgs, Msg};
use crate::party_i::Keys;
use paillier::{EncryptionKey, DecryptionKey};

pub enum ExistingOrNewParty {
	Existing(LocalKey<Secp256k1>),
	New((JoinMessage, Keys)),
}

pub struct PaillierKeys {
	pub ek: EncryptionKey,
	pub dk: DecryptionKey,
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
					sender: join_message.party_index.unwrap(),
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
        O: Push<Msg<Option<RefreshMessage>>>,
    {
		match party_type {
			ExistingOrNewParty::Existing(local_key) => {
				// Broadcast Refresh Message
				let (refresh_message, new_decryption_key) = RefreshMessage::distribute(local_key);
				output.push(Msg {
					sender: local_key.i,
					receiver: None,
					body: refresh_message,
				});
				Ok(Round2 {
					party_type: ExistingOrNewParty::Existing(local_key),
					new_paillier_keys: PaillierKeys {
						refresh_message.ek,
						new_decryption_key,
					}
				})
				
			},
			ExistingOrNewParty::New((join_message, paillier_keys)) => {
				// Do Nothing
				output.push(Msg {
					sender: join_message.party_index.unwrap(),
					receiver: None,
					body: None,
				});
				Ok(Round2 {
					party_type: ExistingOrNewParty::New((join_message, paillier_keys)),
					new_paillier_keys: paillier_keys,
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
	pub new_paillier_keys: PaillierKeys,
}

impl Round2 {}