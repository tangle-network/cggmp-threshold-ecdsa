#![allow(non_snake_case)]

/*
    Multi-party ECDSA

    Copyright 2022 by Webb Technologies.

    This file is part of cggmp library
    (https://github.com/webb-tools/cggmp)

    This file is derived/inspired from Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    cggmp is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/webb-tools/cggmp/blob/main/LICENSE>
*/

use std::fmt::Debug;

use rand::Rng;
use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use centipede::juggling::segmentation::Msegmentation;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};
use curv::BigInt;
use sha2::Sha256;

use crate::Error::{self, InvalidSig, Phase5BadSum, Phase6Error};
use paillier::{
    Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext, RawPlaintext,
};

use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::NiCorrectKeyProof;
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

use crate::ErrorType;
use curv::cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof;

use std::convert::TryInto;

const SECURITY: usize = 256;
const PAILLIER_MIN_BIT_LENGTH: usize = 2047;
const PAILLIER_MAX_BIT_LENGTH: usize = 2048;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Parameters {
    pub threshold: u16,   //t
    pub share_count: u16, //n
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Keys<E: Curve = Secp256k1> {
    pub x_i: Scalar<E>,
    pub pub_X_i: Point<E>,
    // Paillier keys
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    // Party index in the MPC set
    pub party_index: usize,
    pub rid: [u8; SECURITY / 8],
    // Pedersen parameters
    pub N_tilde: BigInt,
    pub s: BigInt,
    pub t: BigInt,
    pub xhi: BigInt,
    pub xhi_inv: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyPrivate {
    x_i: Scalar<Secp256k1>,
    y_i: Scalar<Secp256k1>,
    dk: DecryptionKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenBroadcastMessage1 {
    pub e: EncryptionKey,
    pub dlog_statement: DLogStatement,
    pub com: BigInt,
    pub correct_key_proof: NiCorrectKeyProof,
    pub composite_dlog_proof_base_h1: CompositeDLogProof,
    pub composite_dlog_proof_base_h2: CompositeDLogProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDecommitMessage1 {
    pub blind_factor: BigInt,
    pub y_i: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedKeys {
    pub y: Point<Secp256k1>,
    pub x_i: Scalar<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignKeys {
    pub w_i: Scalar<Secp256k1>,
    pub g_w_i: Point<Secp256k1>,
    pub k_i: Scalar<Secp256k1>,
    pub gamma_i: Scalar<Secp256k1>,
    pub g_gamma_i: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignBroadcastPhase1 {
    pub com: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignDecommitPhase1 {
    pub blind_factor: BigInt,
    pub g_gamma_i: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSignature {
    pub r: Scalar<Secp256k1>,
    pub R: Point<Secp256k1>,
    pub s_i: Scalar<Secp256k1>,
    pub m: BigInt,
    pub y: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRecid {
    pub r: Scalar<Secp256k1>,
    pub s: Scalar<Secp256k1>,
    pub recid: u8,
}

// TODO: Identify if this satisfies the properties of a Ring-Pedersen Scheme
// TODO: Otherwise, implement ring-pedersen:
// https://github.com/taurusgroup/multi-party-sig/blob/main/pkg/math/sample/sample.go#L75
pub fn generate_s_t_N_tilde() -> (BigInt, BigInt, BigInt, BigInt, BigInt) {
    // note, should be safe primes:
    // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();
    let (ek_tilde, dk_tilde) = Paillier::keypair().keys();
    let one = BigInt::one();
    let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
    let s = BigInt::sample_below(&ek_tilde.n);
    let (mut xhi, mut xhi_inv) = loop {
        let xhi_ = BigInt::sample_below(&phi);
        match BigInt::mod_inv(&xhi_, &phi) {
            Some(inv) => break (xhi_, inv),
            None => continue,
        }
    };
    let t = BigInt::mod_pow(&s, &xhi, &ek_tilde.n);
    xhi = BigInt::sub(&phi, &xhi);
    xhi_inv = BigInt::sub(&phi, &xhi_inv);

    (ek_tilde.n, s, t, xhi, xhi_inv)
}

impl Keys {
    pub fn create(index: usize) -> Self {
        let x = Scalar::<Secp256k1>::random();
        let pub_X = Point::generator() * &x;
        let (ek, dk) = Paillier::keypair().keys();
        let rid = rand::thread_rng().gen::<[u8; SECURITY / 8]>();
        let (N_tilde, s, t, xhi, xhi_inv) = generate_s_t_N_tilde();
        Self {
            x_i: x,
            pub_X_i: pub_X,
            dk,
            ek,
            party_index: index,
            rid,
            N_tilde,
            s,
            t,
            xhi,
            xhi_inv,
        }
    }

    // we recommend using safe primes if the code is used in production
    pub fn create_safe_prime(rid: [u8; SECURITY / 8], index: usize) -> Self {
        let x = Scalar::<Secp256k1>::random();
        let pub_X = Point::generator() * &x;

        let (ek, dk) = Paillier::keypair_safe_primes().keys();
        let (N_tilde, s, t, xhi, xhi_inv) = generate_s_t_N_tilde();

        Self {
            x_i: x,
            pub_X_i: pub_X,
            dk,
            ek,
            party_index: index,
            rid,
            N_tilde,
            s,
            t,
            xhi,
            xhi_inv,
        }
    }
    pub fn create_from(x: Scalar<Secp256k1>, rid: [u8; SECURITY / 8], index: usize) -> Self {
        let pub_X = Point::generator() * &x;
        let (ek, dk) = Paillier::keypair().keys();
        let (N_tilde, s, t, xhi, xhi_inv) = generate_s_t_N_tilde();

        Self {
            x_i: x,
            pub_X_i: pub_X,
            dk,
            ek,
            party_index: index,
            rid,
            N_tilde,
            s,
            t,
            xhi,
            xhi_inv,
        }
    }
}
