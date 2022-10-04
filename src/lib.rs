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

pub mod party_i;
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
}

#[derive(Clone, Debug)]
pub struct ErrorType {
	pub error_type: String,
	pub bad_actors: Vec<usize>,
	pub data: Vec<u8>,
}
