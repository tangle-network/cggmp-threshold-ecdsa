#![allow(non_snake_case)]

use std::convert::TryFrom;
use std::iter;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use sha2::Sha256;

use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, P2PMsgs, Store};
use round_based::Msg;

use crate::party_i::{
    LocalSignature, SignBroadcastPhase1, SignDecommitPhase1, SignKeys, SignatureRecid,
};
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof;

use crate::ErrorType;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("round 1: {0:?}")]
    Round1(ErrorType),
    #[error("round 2 stage 3: {0:?}")]
    Round2Stage3(crate::Error),
    #[error("round 2 stage 4: {0:?}")]
    Round2Stage4(ErrorType),
    #[error("round 3: {0:?}")]
    Round3(ErrorType),
    #[error("round 5: {0:?}")]
    Round5(ErrorType),
    #[error("round 6: verify proof: {0:?}")]
    Round6VerifyProof(ErrorType),
    #[error("round 6: check sig: {0:?}")]
    Round6CheckSig(crate::Error),
    #[error("round 7: {0:?}")]
    Round7(crate::Error),
}

pub struct Round1 {
    pub party_i: u16,
    pub t: u16,
    pub n: u16,
}

impl Round1 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<Vec<u8>>>,
    {
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: vec![],
        });
        Ok(Round1 {
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}
