use curv::{
	elliptic::curves::{Curve, Point},
	BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use paillier::{DecryptionKey, EncryptionKey, RawCiphertext};
use sha2::Sha256;

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

pub struct PreSigningSecrets {
	pub x_i: BigInt,
	pub y_i: Option<BigInt>,
	pub ek: EncryptionKey,
	pub dk: DecryptionKey,
}

pub struct PreSigningP2PMessage1<E: Curve> {
	pub ssid: SSID<E>,
	pub i: u16,
	pub K_i: BigInt,
	pub G_i: BigInt,
	pub ek: EncryptionKey,
	pub psi_j_i: crate::utilities::enc::PaillierEncryptionInRangeProof<E, Sha256>,
	pub enc_j_statement: crate::utilities::enc::PaillierEncryptionInRangeStatement<E, Sha256>,
}

pub struct PreSigningP2PMessage2<E: Curve> {
	pub ssid: SSID<E>,
	pub Gamma_i: Point<E>,
	D_j_i: BigInt,
	F_j_i: BigInt,
	D_hat_j_i: BigInt,
	F_hat_j_i: BigInt,
	psi_j_i: crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeProof<E, Sha256>,
	psi_hat_j_i: crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeProof<E, Sha256>,
	psi_prime_j_i:
		crate::utilities::log_star::KnowledgeOfExponentPaillierEncryptionProof<E, Sha256>,
	statement_psi_j_i:
		crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeStatement<E, Sha256>,
	statement_psi_prime_j_i:
		crate::utilities::aff_g::PaillierAffineOpWithGroupComInRangeStatement<E, Sha256>,
	statement_psi_hat_j_i:
		crate::utilities::log_star::KnowledgeOfExponentPaillierEncryptionStatement<E, Sha256>,
}

pub struct PreSigningP2PMessage3<E: Curve> {
	pub ssid: SSID<E>,
	pub delta_i: BigInt,
	pub Delta_i: Point<E>,
	psi_prime_prime_j_i:
		crate::utilities::log_star::KnowledgeOfExponentPaillierEncryptionProof<E, Sha256>,
}
