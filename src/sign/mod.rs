use std::collections::HashMap;

use curv::{
	elliptic::curves::{Curve, Point},
	BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use paillier::{DecryptionKey, EncryptionKey, RawCiphertext};
use sha2::Sha256;

use crate::utilities::{
	aff_g::{
		PaillierAffineOpWithGroupComInRangeProof, PaillierAffineOpWithGroupComInRangeStatement,
	},
	dec_q::PaillierDecryptionModQProof,
	mul::{PaillierMulProof, PaillierMulStatement},
};

pub mod rounds;
pub mod state_machine;

pub struct SSID<E: Curve> {
	// Group generator and order
	pub g: Point<E>,
	pub q: BigInt,
	// Parties
	pub P: Vec<u16>,
	pub rid: [u8; 32],
	pub X: LocalKey<E>,
	pub Y: Option<Point<E>>,
	// Pedersen parameters
	pub N: BigInt,
	pub S: BigInt,
	pub T: BigInt,
}

pub struct SigningBroadcastMessage1<E: Curve> {
	pub ssid: SSID<E>,
	pub i: u16,
	pub sigma_i: BigInt,
}

pub struct SigningOutput<E: Curve> {
	ssid: SSID<E>,
	m: BigInt,
	r: BigInt,
	sigma: BigInt,
}

pub struct SigningIdentifiableAbortMessage<E: Curve> {
	
}
