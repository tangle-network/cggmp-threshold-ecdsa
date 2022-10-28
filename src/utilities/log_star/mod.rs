#![allow(non_snake_case)]
/*
	CGGMP Threshold ECDSA

	Copyright 2022 by Webb Technologies

	This file is part of CGGMP Threshold ECDSA library
	(https://github.com/webb-tools/cggmp-threshold-ecdsa)

	CGGMP Threshold ECDSA is free software: you can redistribute
	it and/or modify it under the terms of the GNU General Public
	License as published by the Free Software Foundation, either
	version 3 of the License, or (at your option) any later version.

	@license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

//! Knowledge of Exponent vs Paillier Encryption – Π^{log∗}
//!
//! Common input is (G, q, N0, C, X, g).
//! The Prover has secret input (x,ρ) such that
//!         x ∈ ± 2l, and C = (1 + N0)^x · ρ^N0 mod N0^2 and X = g^x    ∈ G.