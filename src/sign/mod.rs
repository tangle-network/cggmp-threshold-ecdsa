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

use curv::{elliptic::curves::Curve, BigInt};
use serde::{Deserialize, Serialize};

use sha2::Sha256;

use crate::utilities::dec_q::{
    PaillierDecryptionModQProof, PaillierDecryptionModQStatement,
};
use tss_core::zkproof::aff_g::{PiAffGProof, PiAffGStatement};
use tss_core::zkproof::mul_star::{PiMulStarProof, PiMulStarStatement};

use crate::presign::SSID;
pub mod rounds;
pub mod state_machine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningBroadcastMessage1<E: Curve> {
    pub ssid: SSID<E>,
    pub i: u16,
    pub sigma_i: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningOutput<E: Curve> {
    pub ssid: SSID<E>,
    pub m: BigInt,
    pub r: BigInt,
    pub sigma: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningIdentifiableAbortMessage<E: Curve> {
    pub i: u16,
    pub proofs_D_hat_j_i: HashMap<(u16, u16), PiAffGProof<E, Sha256>>,
    pub statements_D_hat_j_i: HashMap<(u16, u16), PiAffGStatement<E, Sha256>>,
    pub proof_H_hat_i: HashMap<u16, PiMulStarProof<E, Sha256>>,
    pub statement_H_hat_i: HashMap<u16, PiMulStarStatement<E, Sha256>>,
    pub proof_sigma_i: HashMap<u16, PaillierDecryptionModQProof<E, Sha256>>,
    pub statement_sigma_i:
        HashMap<u16, PaillierDecryptionModQStatement<E, Sha256>>,
}
