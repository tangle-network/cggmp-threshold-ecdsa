use crate::keygen::rounds::*;
use fs_dkr::{add_party_message::*, refresh_message::*, error::*};
use round_based::{containers::BroadcastMsgs, Msg};
use crate::party_i::Keys;
use paillier::{EncryptionKey, DecryptionKey};
use crate::party_i::KeyRefreshBroadcastMessageRound1;
use sha2::Sha256;


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
	t: usize,
	n: usize,
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
					t: self.t,
					n: self.n,
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
					t: self.t,
					n: self.n,
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
	t: usize,
	n: usize,
}

impl Round1 {
	pub fn proceed<O>(self, input: BrodcastMsgs<Option<JoinMessage>>, mut output: O) -> Result<Round2>
    where
        O: Push<Msg<Option<FsDkrResult<RefreshMessage<Secp256k1, Sha256>>>>>, 
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
				let refresh_message_result = RefreshMessage::replace(join_message_slice, &mut local_key);
				let new_paillier_ek = refresh_message_result.unwrap().0.ek;
				let new_paillier_dk = refresh_message_result.unwrap().1;
				output.push(Msg {
					sender: local_key.i,
					receiver: None,
					body: refresh_message_result,
					
				});
				Ok(Round2 {
					party_type: ExistingOrNewParty::Existing(local_key),
					join_messages: join_message_vec,
					new_paillier_keys: PaillierKeys {
						ek: new_paillier_ek,
						dk: new_paillier_dk,
					},
					t: self.t,
					n: self.n,
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
					new_paillier_keys: PaillierKeys {
						ek: paillier_keys.ek,
						dk: paillier_keys.dk,
					},
					t: self.t,
					n: self.n,
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
	pub new_paillier_keys: PaillierKeys,
	t: usize,
	n: usize,
}

impl Round2 {
	pub fn proceed(self, input: BrodcastMsgs<Option<FsDkrResult<RefreshMessage<Secp256k1, Sha256>>>>,) -> Result<LocalKey<Secp256k1>> {
		let refresh_message_option_vec = input.into_vec();
		let mut refresh_message_vec: Vec<FsDkrResult<RefreshMessage<Secp256k1, Sha256>>> = Vec::new();
		for refresh_message_option in refresh_message_option_vec {
			match elem {
				Some(refresh_message_option) => {
					refresh_message_vec.push(refresh_message_option.unwrap().0)
				},
				_ => {},
			}
		}

		match party_type {
			ExistingOrNewParty::Existing(local_key) => {
				let join_message_slice = self.join_messages.as_slice();
				let refresh_message_slice = refresh_message_vec.as_slice();
				RefreshMessage::collect(refresh_message_slice, &mut local_key, self.new_paillier_keys.dk, join_message_slice,);
				Ok(local_key)

			},
			ExistingOrNewParty::New((join_message, paillier_keys)) => {
				let join_message_slice = self.join_messages.as_slice();
				let refresh_message_slice = refresh_message_vec.as_slice();
				// TODO: Not sure if refresh_message_vec.len() is the right value for n.
				JoinMessage::collect(refresh_message_slice, paillier_keys, join_message_slice, self.t, self.n)
			},
		}
	}

	pub fn is_expensive(&self) -> bool {
		true
    }  
}