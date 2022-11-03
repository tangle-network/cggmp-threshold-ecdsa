use std::collections::HashMap;

use curv::{elliptic::curves::Secp256k1, BigInt};
use round_based::{
	containers::{push::Push, BroadcastMsgs, BroadcastMsgsStore},
	Msg,
};

use crate::presign::{PresigningOutput, PresigningTranscript};

use super::{SigningBroadcastMessage1, SSID};

pub struct Round0 {
	pub ssid: SSID<Secp256k1>,
	pub l: usize, // This is the number of presignings to run in parallel
	pub m: BigInt,
	pub presigning_data:
		HashMap<u16, (PresigningOutput<Secp256k1>, PresigningTranscript<Secp256k1>)>,
}

impl Round0 {
	pub fn proceed<O>(self, mut output: O) -> Result<Round1>
	where
		O: Push<Msg<SigningBroadcastMessage1<Secp256k1>>>,
	{
		if self.presigning_data.get(self.l).is_some() {
			let (output, transcript) = self.presigning_data.get(self.l).unwrap();
			let r = output.R.x_coord().unwrap();
			let sigma_i = output.k_i.mul(self.m).add(r.mul(output.chi_i));
			let body = SigningBroadcastMessage1 { ssid: self.ssid, i: self.ssid.X.i, sigma_i };
			output.push(Msg { sender: self.ssid.X.i, receiver: None, body });
			// TODO: Erase output from memory
			Ok(Round1 {
				i: self.ssid.X.i,
				r,
				m: self.m,
				presigning_transcript: transcript,
				sigma: sigma_i,
			})
		} else {
			Err(format!("No offline stage for {}", self.l))
		}
	}
	pub fn is_expensive(&self) -> bool {
		false
	}
}

pub struct Round1 {
	i: u16,
	r: BigInt,
	m: BigInt,
	presigning_transcript: PresigningTranscript<Secp256k1>,
	sigma: BigInt,
}

impl Round1 {
	pub fn proceed<O>(
		self,
		input: BroadcastMsgs<SigningBroadcastMessage1<Secp256k1>>,
		mut output: O,
	) -> Result<Round2>
	where
		O: Push<Msg<()>>,
	{
		let sigmas: HashMap<u16, BigInt> = HashMap::new();
		sigmas.insert(self.i, self.sigma);
		for msg in input.into_vec() {
			sigmas.insert(msg.i, msg.sigma_i);
		}
		let sigma = sigmas.values().into_iter().fold(BigInt::zero(), |acc, x| acc.add(x));

		// Verify (r, sigma) is a valid signature
	}

	pub fn is_expensive(&self) -> bool {
		false
	}

	pub fn expects_messages(i: u16, n: u16) -> Round0Messages {
		BroadcastMsgsStore::new(i, n)
	}
}

pub struct Round2 {}

type Result<T> = std::result::Result<T, Error>;
