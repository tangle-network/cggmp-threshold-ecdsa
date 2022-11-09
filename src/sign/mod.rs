use std::collections::HashMap;

use curv::{
	elliptic::curves::{Curve, Point},
	BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use paillier::{DecryptionKey, EncryptionKey, RawCiphertext};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::utilities::{
	aff_g::{
		PaillierAffineOpWithGroupComInRangeProof, PaillierAffineOpWithGroupComInRangeStatement,
	},
	dec_q::{PaillierDecryptionModQProof, PaillierDecryptionModQStatement},
	mul::{PaillierMulProof, PaillierMulStatement},
	mul_star::{
		PaillierMultiplicationVersusGroupProof, PaillierMultiplicationVersusGroupStatement,
	},
};

use crate::presign::SSID;
pub mod rounds;
pub mod state_machine;

#[derive(Debug, Clone)]
pub struct SigningBroadcastMessage1<E: Curve> {
	pub ssid: SSID<E>,
	pub i: u16,
	pub sigma_i: BigInt,
}

#[derive(Debug, Clone)]
pub struct SigningOutput<E: Curve> {
	pub ssid: SSID<E>,
	pub m: BigInt,
	pub r: BigInt,
	pub sigma: BigInt,
}

#[derive(Debug, Clone)]
pub struct SigningIdentifiableAbortMessage<E: Curve> {
	pub proofs_D_hat_j_i: HashMap<(u16, u16), PaillierAffineOpWithGroupComInRangeProof<E, Sha256>>,
	pub statements_D_hat_j_i:
		HashMap<(u16, u16), PaillierAffineOpWithGroupComInRangeStatement<E, Sha256>>,
	pub proof_H_hat_i: HashMap<u16, PaillierMultiplicationVersusGroupProof<E, Sha256>>,
	pub statement_H_hat_i: HashMap<u16, PaillierMultiplicationVersusGroupStatement<E, Sha256>>,
	pub proof_sigma_i: HashMap<u16, PaillierDecryptionModQProof<E, Sha256>>,
	pub statement_sigma_i: HashMap<u16, PaillierDecryptionModQStatement<E, Sha256>>,
}
