/*
	CGGMP Threshold ECDSA

	Copyright 2022 by Webb Technologies.

	This file is part of cggmp library
	(https://github.com/webb-tools/cggmp-threshold-ecdsa)

	This file is derived/inspired from Multi-party ECDSA library
	(https://github.com/KZen-networks/multi-party-ecdsa)

	cggmp-threshold-ecdsa is free software: you can redistribute
	it and/or modify it under the terms of the GNU General Public
	License as published by the Free Software Foundation, either
	version 3 of the License, or (at your option) any later version.

	@license GPL-3.0+ <https://github.com/webb-tools/cggmp/blob/main/LICENSE>
*/

#![allow(non_snake_case)]
#![feature(box_patterns)]

use serde::{Deserialize, Serialize};

pub mod party_i;
pub mod presign;
pub mod refresh;
pub mod sign;
pub mod traits;
pub mod utilities;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
	InvalidKey,
	InvalidSS,
	InvalidCom,
	InvalidSig,
	Phase5BadSum,
	Phase6Error,
	AffineWithGroupComRangeProofError,
}

#[derive(Clone, Debug)]
pub struct ErrorType {
	pub error_type: String,
	pub bad_actors: Vec<usize>,
	pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofVerificationErrorData {
	proof_symbol: String,
	verifying_party: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoOfflineStageErrorData {
	l: usize,
}
