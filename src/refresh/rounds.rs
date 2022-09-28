use crate::keygen::rounds::*;
use fs_dkr::{add_party_message::*, refresh_message::*};
use round_based::Msg;

pub struct Round0 {
	local_key_option: Option<LocalKey<Secp256k1>>
}

impl Round0 {
	pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<>>,
    {
        // Match on local_key
		match local_key_option {
			Some(local_key) => {
				// Push JoinMessage to output
				output.push(Msg {
					sender: local_key.i,
					receiver: None,
					body: None,
				});
				// Send local key to round 1
				Ok(Round1 {
					local_key: local_key,
				})
			},
			None => {
				// Push JoinMessage to output
				// Generate new local key
			}
		}

    }
    pub fn is_expensive(&self) -> bool {
		true
    }  
}

pub struct Round1 {
	local_key: LocalKey<Secp256k1>,
}

impl Round1 {

}

pub struct Round2 {
	local_key: LocalKey<Secp256k1>,
}

impl Round2 {

}