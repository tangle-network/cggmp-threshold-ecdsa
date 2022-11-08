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
	proofs_D_hat_j_i: HashMap<u16, PaillierAffineOpWithGroupComInRangeProof<E, Sha256>>,
	statements_D_hat_j_i: HashMap<u16, PaillierAffineOpWithGroupComInRangeStatement<E, Sha256>>,
	H_hat_i_proof: PaillierMultiplicationVersusGroupProof<E, Sha256>,
	statement_H_hat_i: PaillierMultiplicationVersusGroupStatement<E, Sha256>,
	sigma_i_proof: PaillierDecryptionModQProof<E, Sha256>,
	statement_sigma_i: PaillierDecryptionModQStatement<E, Sha256>,
}
