/*
    CGGMP Threshold ECDSA

    Copyright 2022 by Webb Technologies.

    This file is part of cggmp library
    (https://github.com/webb-tools/cggmp-threshold-ecdsa)

    cggmp-threshold-ecdsa is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/webb-tools/cggmp/blob/main/LICENSE>
*/

use std::collections::HashMap;

use curv::{
	arithmetic::Zero,
	elliptic::curves::{Curve, Point},
	BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use paillier::{DecryptionKey, EncryptionKey};
use sha2::Sha256;

use crate::utilities::{
    aff_g::{
        PaillierAffineOpWithGroupComInRangeProof,
        PaillierAffineOpWithGroupComInRangeStatement,
    },
    dec_q::{PaillierDecryptionModQProof, PaillierDecryptionModQStatement},
    log_star::{
        KnowledgeOfExponentPaillierEncryptionProof,
        KnowledgeOfExponentPaillierEncryptionStatement,
    },
    mul::{PaillierMulProof, PaillierMulStatement},
};
use tss_core::zkproof::enc::{
    PaillierEncryptionInRangeProof, PaillierEncryptionInRangeStatement,
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub mod rounds;
pub mod state_machine;

pub fn DEFAULT_ENCRYPTION_KEY() -> EncryptionKey {
    EncryptionKey {
        n: BigInt::zero(),
        nn: BigInt::zero(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl<E: Curve> Zeroize for SSID<E> {
    fn zeroize(&mut self) {
        self.q.zeroize();
        self.P.zeroize();
        self.rid.zeroize();
        // X zeroize
        self.X.paillier_dk.p.zeroize();
        self.X.paillier_dk.q.zeroize();
        // TODO: Ensure this clears memory or zeroize directly
        // FIXME: This is a hack in the meantime until we are sure the memory is
        // cleared.
        self.X.pk_vec = vec![];

        for encryption_key in self.X.paillier_key_vec.iter_mut() {
            encryption_key.n.zeroize();
            encryption_key.nn.zeroize();
        }
        // TODO: Zeroize directly if this is insufficient
        self.X.y_sum_s = Point::zero();
        for dlog_statement in self.X.h1_h2_n_tilde_vec.iter_mut() {
            dlog_statement.modulus.zeroize();
            dlog_statement.base.zeroize();
            dlog_statement.value.zeroize();
        }
        self.X.vss_scheme.parameters.threshold.zeroize();
        self.X.vss_scheme.parameters.share_count.zeroize();
        // TODO: Zeroize directly if this is insufficient
        self.X.vss_scheme.commitments = vec![];
        self.X.i.zeroize();
        self.X.t.zeroize();
        self.X.n.zeroize();
        // Y zeroize
        // TODO: Zeroize directly if this is insufficient
        self.Y = None;
        self.N.zeroize();
        self.S.zeroize();
        self.T.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreSigningSecrets {
    pub x_i: BigInt,
    pub y_i: Option<BigInt>,
    pub ek: EncryptionKey,
    pub dk: DecryptionKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreSigningP2PMessage1<E: Curve> {
    pub ssid: SSID<E>,
    pub i: u16,
    pub K_i: BigInt,
    pub G_i: BigInt,
    pub ek: EncryptionKey,
    pub psi_0_j_i: PaillierEncryptionInRangeProof<E, Sha256>,
    pub enc_j_statement: PaillierEncryptionInRangeStatement<E, Sha256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreSigningP2PMessage2<E: Curve> {
    pub ssid: SSID<E>,
    pub i: u16,
    pub Gamma_i: Point<E>,
    pub D_j_i: BigInt,
    pub F_j_i: BigInt,
    pub D_hat_j_i: BigInt,
    pub F_hat_j_i: BigInt,
    pub psi_j_i: PaillierAffineOpWithGroupComInRangeProof<E, Sha256>,
    pub statement_psi_j_i:
        PaillierAffineOpWithGroupComInRangeStatement<E, Sha256>,
    pub psi_hat_j_i: PaillierAffineOpWithGroupComInRangeProof<E, Sha256>,
    pub statement_psi_hat_j_i:
        PaillierAffineOpWithGroupComInRangeStatement<E, Sha256>,
    pub psi_prime_j_i: KnowledgeOfExponentPaillierEncryptionProof<E, Sha256>,
    pub statement_psi_prime_j_i:
        KnowledgeOfExponentPaillierEncryptionStatement<E, Sha256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreSigningP2PMessage3<E: Curve> {
    pub ssid: SSID<E>,
    pub i: u16,
    pub delta_i: BigInt,
    pub Delta_i: Point<E>,
    pub psi_prime_prime_j_i:
        KnowledgeOfExponentPaillierEncryptionProof<E, Sha256>,
    pub statement_psi_prime_prime_j_i:
        KnowledgeOfExponentPaillierEncryptionStatement<E, Sha256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresigningOutput<E: Curve> {
    pub ssid: SSID<E>,
    pub R: Point<E>,
    pub i: u16,
    pub k_i: BigInt,
    pub chi_i: BigInt,
}

impl<E: Curve> Zeroize for PresigningOutput<E> {
    fn zeroize(&mut self) {
        self.ssid.zeroize();
        // TODO: zeroize R
        self.R = Point::zero();
        self.i.zeroize();
        self.k_i.zeroize();
        self.chi_i.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub D_j: HashMap<u16, BigInt>,
    pub D_hat_j: HashMap<u16, BigInt>,
    pub F_j: HashMap<u16, BigInt>,
    pub F_hat_j: HashMap<u16, BigInt>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifiableAbortBroadcastMessage<E: Curve> {
    pub i: u16,
    pub statements_D_j_i: HashMap<
        (u16, u16),
        PaillierAffineOpWithGroupComInRangeStatement<E, Sha256>,
    >,
    pub proofs_D_j_i: HashMap<
        (u16, u16),
        PaillierAffineOpWithGroupComInRangeProof<E, Sha256>,
    >,
    pub statement_H_i: PaillierMulStatement<E, Sha256>,
    pub proof_H_i: PaillierMulProof<E, Sha256>,
    pub statement_delta_i:
        HashMap<u16, PaillierDecryptionModQStatement<E, Sha256>>,
    pub proof_delta_i: HashMap<u16, PaillierDecryptionModQProof<E, Sha256>>,
}
