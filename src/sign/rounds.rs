use std::{collections::HashMap, ops::Add};

use curv::{
	elliptic::curves::{Point, Scalar, Secp256k1},
	BigInt,
};
use round_based::{
	containers::{push::Push, BroadcastMsgs, BroadcastMsgsStore},
	Msg,
};

use crate::presign::{PresigningOutput, PresigningTranscript};

use super::{SigningBroadcastMessage1, SigningIdentifiableAbortMessage, SigningOutput, SSID};

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
				ssid: self.ssid,
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
	pub ssid: SSID<Secp256k1>,
	pub i: u16,
	pub r: BigInt,
	pub m: BigInt,
	pub presigning_transcript: PresigningTranscript<Secp256k1>,
	pub sigma: BigInt,
}

impl Round1 {
	pub fn proceed<O>(
		self,
		input: BroadcastMsgs<SigningBroadcastMessage1<Secp256k1>>,
		mut output: O,
	) -> Result<Round2>
	where
		O: Push<Msg<SigningIdentifiableAbortMessage<Secp256k1>>>,
	{
		let sigmas: HashMap<u16, BigInt> = HashMap::new();
		sigmas.insert(self.i, self.sigma);
		for msg in input.into_vec() {
			sigmas.insert(msg.i, msg.sigma_i);
		}
		let sigma: BigInt = sigmas.values().into_iter().fold(BigInt::zero(), |acc, x| acc.add(x));

		// Verify (r, sigma) is a valid signature
		let sigma_inv = BigInt::mod_inv(sigma);
		let m_sigma_inv = self.m.mul(sigma_inv);
		let r_sigma_inv = self.r.mul(sigma_inv);
		let g = Point::<Secp256k1>::generator();
		let X = self.ssid.X.public_key();
		let x_projection = (g * Scalar::from_bigint(m_sigma_inv))
			.add(X * Scalar::from_bigint(r_sigma_inv))
			.x_coord();

		if self.r == x_projection {
			let signing_output = SigningOutput { ssid: self.ssid, m: self.m, r: self.r, sigma };
			output.push(Msg { sender: self.ssid.X.i, receiver: None, body: None });
			Ok(Round2 { output: Some(signing_output) })
		} else {
			Ok(Round2 { output: None })
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
	output: Option<SigningOutput<Secp256k1>>,
}

type Result<T> = std::result::Result<T, Error>;
