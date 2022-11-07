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
	enc::{PaillierEncryptionInRangeProof, PaillierEncryptionInRangeStatement},
	log_star::{
		KnowledgeOfExponentPaillierEncryptionProof, KnowledgeOfExponentPaillierEncryptionStatement,
	},
	mul::{PaillierMulProof, PaillierMulStatement},
};

use zeroize::Zeroize;

pub mod rounds;
pub mod state_machine;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct PreSigningSecrets {
	pub x_i: BigInt,
	pub y_i: Option<BigInt>,
	pub ek: EncryptionKey,
	pub dk: DecryptionKey,
}

#[derive(Debug, Clone)]
pub struct PreSigningP2PMessage1<E: Curve> {
	pub ssid: SSID<E>,
	pub i: u16,
	pub K_i: BigInt,
	pub G_i: BigInt,
	pub ek: EncryptionKey,
	pub psi_0_j_i: PaillierEncryptionInRangeProof<E, Sha256>,
	pub enc_j_statement: PaillierEncryptionInRangeStatement<E, Sha256>,
}

#[derive(Debug, Clone)]
pub struct PreSigningP2PMessage2<E: Curve> {
	pub ssid: SSID<E>,
	pub i: u16,
	pub Gamma_i: Point<E>,
	pub D_j_i: BigInt,
	pub F_j_i: BigInt,
	pub D_hat_j_i: BigInt,
	pub F_hat_j_i: BigInt,
	pub psi_j_i: PaillierAffineOpWithGroupComInRangeProof<E, Sha256>,
	pub statement_psi_j_i: PaillierAffineOpWithGroupComInRangeStatement<E, Sha256>,
	pub psi_hat_j_i: PaillierAffineOpWithGroupComInRangeProof<E, Sha256>,
	pub statement_psi_hat_j_i: PaillierAffineOpWithGroupComInRangeStatement<E, Sha256>,
	pub psi_prime_j_i: KnowledgeOfExponentPaillierEncryptionProof<E, Sha256>,
	pub statement_psi_prime_j_i: KnowledgeOfExponentPaillierEncryptionStatement<E, Sha256>,
}

#[derive(Debug, Clone)]
pub struct PreSigningP2PMessage3<E: Curve> {
	pub ssid: SSID<E>,
	pub i: u16,
	pub delta_i: BigInt,
	pub Delta_i: Point<E>,
	pub psi_prime_prime_j_i: KnowledgeOfExponentPaillierEncryptionProof<E, Sha256>,
	pub statement_psi_prime_prime_j_i: KnowledgeOfExponentPaillierEncryptionStatement<E, Sha256>,
}

#[derive(Zeroize, Debug, Clone)]
pub struct PresigningOutput<E: Curve> {
	pub ssid: SSID<E>,
	pub R: Point<E>,
	pub i: u16,
	pub k_i: BigInt,
	pub chi_i: BigInt,
}

#[derive(Debug, Clone)]
pub struct PresigningTranscript<E: Curve> {
	pub ssid: SSID<E>,
	pub secrets: PreSigningSecrets,
	pub eks: HashMap<u16, EncryptionKey>,
	pub gamma_i: BigInt,
	pub Gamma_i: Point<E>,
	pub Gammas: HashMap<u16, Point<E>>,
	pub Gamma: Point<E>,
	pub k_i: BigInt,
	pub nu_i: BigInt,
	pub rho_i: BigInt,
	pub G_i: BigInt,
	pub K_i: BigInt,
	pub G: HashMap<u16, BigInt>,
	pub K: HashMap<u16, BigInt>,
	pub beta_i: HashMap<u16, BigInt>,
	pub beta_hat_i: HashMap<u16, BigInt>,
	pub r_i: HashMap<u16, BigInt>,
	pub r_hat_i: HashMap<u16, BigInt>,
	pub s_i: HashMap<u16, BigInt>,
	pub s_hat_i: HashMap<u16, BigInt>,
	pub delta_i: BigInt,
	pub chi_i: BigInt,
	pub Delta_i: Point<E>,
	pub deltas: HashMap<u16, BigInt>,
	pub Deltas: HashMap<u16, Point<E>>,
	pub delta: BigInt,
	pub D_i: HashMap<u16, BigInt>,
	pub D_hat_i: HashMap<u16, BigInt>,
	pub F_i: HashMap<u16, BigInt>,
	pub F_hat_i: HashMap<u16, BigInt>,
	pub alpha_i: HashMap<u16, BigInt>,
	pub alpha_hat_i: HashMap<u16, BigInt>,
	pub S: HashMap<u16, BigInt>,
	pub T: HashMap<u16, BigInt>,
	pub N_hats: HashMap<u16, BigInt>,
}

#[derive(Debug, Clone)]
pub struct IdentifiableAbortBroadcastMessage<E: Curve> {
	pub statements_D_j_i:
		HashMap<(u16, u16), PaillierAffineOpWithGroupComInRangeStatement<E, Sha256>>,
	pub proofs_D_j_i: HashMap<(u16, u16), PaillierAffineOpWithGroupComInRangeProof<E, Sha256>>,
	pub statement_H_i: PaillierMulStatement<E, Sha256>,
	pub H_i_proof: PaillierMulProof<E, Sha256>,
	pub statement_delta_i: PaillierDecryptionModQProof<E, Sha256>,
	pub delta_i_proof: PaillierDecryptionModQProof<E, Sha256>,
}
