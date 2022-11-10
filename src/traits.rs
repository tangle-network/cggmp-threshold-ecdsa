/*
	Multi-party ECDSA

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
pub trait RoundBlame {
	/// Retrieves a list of uncorporative parties
	///
	/// Returns a numbers of messages yet to recieve and list of parties to send messages for the
	/// current round
	fn round_blame(&self) -> (u16, Vec<u16>);
}
