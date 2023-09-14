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

use super::{
	rounds::{Round0, Round1, Round2, Round3, Round4},
	IdentifiableAbortBroadcastMessage, PreSigningP2PMessage1, PreSigningP2PMessage2,
	PreSigningP2PMessage3, PreSigningSecrets, PresigningOutput, PresigningTranscript, SSID,
};

use curv::{elliptic::curves::Secp256k1, BigInt};
use private::InternalError;
use round_based::{
	containers::{
		push::{Push, PushExt},
		BroadcastMsgs, MessageStore, P2PMsgs, Store, StoreErr,
	},
	IsCritical, Msg, StateMachine,
};

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, mem::replace, time::Duration};
use thiserror::Error;

// NOTE: This is a hack since in the 1st round we will need to broadcast and send P2P
// messages, but the round-based library doesn't support this. So we will use the
// `P2PMsgs` to send all the data we need peers to receive.
// FIXME: If we re-design `round-based-traits` to support sending 2 types of messages
// in the same round, we can remove this hack.
pub type Round0Messages = Store<P2PMsgs<PreSigningP2PMessage1<Secp256k1>>>;
pub type Round1Messages = Store<P2PMsgs<PreSigningP2PMessage2<Secp256k1>>>;
pub type Round2Messages = Store<P2PMsgs<PreSigningP2PMessage3<Secp256k1>>>;
pub type Round3Messages =
	Store<BroadcastMsgs<Option<IdentifiableAbortBroadcastMessage<Secp256k1>>>>;

pub struct PreSigning {
	// Current round
	round: R,

	// Messages
	round0_msgs: Option<Round0Messages>,
	round1_msgs: Option<Round1Messages>,
	round2_msgs: Option<Round2Messages>,
	round3_msgs: Option<Round3Messages>,

	// Message queue
	msgs_queue: Vec<Msg<ProtocolMessage>>,

	party_i: u16,

	party_n: u16,
}

impl PreSigning {
	pub fn new(
		ssid: SSID<Secp256k1>,
		secrets: PreSigningSecrets,
		S: HashMap<u16, BigInt>,
		T: HashMap<u16, BigInt>,
		N_hats: HashMap<u16, BigInt>,
		l: usize,
	) -> Result<Self> {
		let n = ssid.P.len();
		if n < 2 {
			return Err(Error::TooFewParties)
		}

		let i = ssid.X.i;

		let mut state = Self {
			round: R::Round0(Box::new(Round0 { ssid, secrets, S, T, N_hats, l })),

			round0_msgs: Some(Round1::expects_messages(i, n as u16)),
			round1_msgs: Some(Round2::expects_messages(i, n as u16)),
			round2_msgs: Some(Round3::expects_messages(i, n as u16)),
			round3_msgs: Some(Round4::expects_messages(i, n as u16)),

			msgs_queue: vec![],
			party_i: i,
			party_n: n as u16,
		};

		state.proceed_round(false)?;
		Ok(state)
	}

	fn gmap_queue<'a, T, F>(&'a mut self, mut f: F) -> impl Push<Msg<T>> + 'a
	where
		F: FnMut(T) -> M + 'a,
	{
		(&mut self.msgs_queue).gmap(move |m: Msg<T>| m.map_body(|m| ProtocolMessage(f(m))))
	}

	/// Proceeds round state if it received enough messages and if it's cheap to compute or
	/// `may_block == true`
	fn proceed_round(&mut self, may_block: bool) -> Result<()> {
		let store1_wants_more = self.round0_msgs.as_ref().map(|s| s.wants_more()).unwrap_or(false);
		let store2_wants_more = self.round1_msgs.as_ref().map(|s| s.wants_more()).unwrap_or(false);
		let store3_wants_more = self.round2_msgs.as_ref().map(|s| s.wants_more()).unwrap_or(false);
		let store4_wants_more = self.round3_msgs.as_ref().map(|s| s.wants_more()).unwrap_or(false);

		let next_state: R;

		let try_again: bool = match replace(&mut self.round, R::Gone) {
			R::Round0(round) if !round.is_expensive() || may_block => {
				next_state = round
					.proceed(self.gmap_queue(M::Round1))
					.map(|msg| R::Round1(Box::new(msg)))
					.map_err(|_e| Error::ProceedRound { msg_round: 0 })?;
				true
			},
			s @ R::Round0(_) => {
				next_state = s;
				false
			},
			R::Round1(round) if !store1_wants_more && (!round.is_expensive() || may_block) => {
				let store = self.round0_msgs.take().ok_or(InternalError::StoreGone)?;
				let msgs = store.finish().map_err(InternalError::RetrieveRoundMessages)?;
				next_state = round
					.proceed(msgs, self.gmap_queue(M::Round2))
					.map(|msg| R::Round2(Box::new(msg)))
					.map_err(|_e| Error::ProceedRound { msg_round: 1 })?;
				true
			},
			s @ R::Round1(_) => {
				next_state = s;
				false
			},
			R::Round2(round) if !store2_wants_more && (!round.is_expensive() || may_block) => {
				let store = self.round1_msgs.take().ok_or(InternalError::StoreGone)?;
				let msgs = store.finish().map_err(InternalError::RetrieveRoundMessages)?;
				next_state = round
					.proceed(msgs, self.gmap_queue(M::Round3))
					.map(|msg| R::Round3(Box::new(msg)))
					.map_err(|_e| Error::ProceedRound { msg_round: 2 })?;
				true
			},
			s @ R::Round2(_) => {
				next_state = s;
				false
			},
			R::Round3(round) if !store3_wants_more && (!round.is_expensive() || may_block) => {
				let store = self.round2_msgs.take().ok_or(InternalError::StoreGone)?;
				let msgs = store.finish().map_err(InternalError::RetrieveRoundMessages)?;
				next_state = round
					.proceed(msgs, self.gmap_queue(M::Round4))
					.map(|msg| R::Round4(Box::new(msg)))
					.map_err(|_e| Error::ProceedRound { msg_round: 3 })?;
				true
			},
			s @ R::Round3(_) => {
				next_state = s;
				false
			},
			R::Round4(round) if !store4_wants_more && (!round.is_expensive() || may_block) => {
				let store = self.round3_msgs.take().ok_or(InternalError::StoreGone)?;
				let msgs = store.finish().map_err(InternalError::RetrieveRoundMessages)?;
				next_state = round
					.proceed(msgs)
					.map(|msg| R::Final(Box::new(msg)))
					.map_err(|_e| Error::ProceedRound { msg_round: 4 })?;
				true
			},
			s @ R::Round4(_) => {
				next_state = s;
				false
			},
			s @ R::Final(_) | s @ R::Gone => {
				next_state = s;
				false
			},
		};
		self.round = next_state;
		if try_again {
			self.proceed_round(may_block)
		} else {
			Ok(())
		}
	}
}

impl StateMachine for PreSigning {
	type MessageBody = ProtocolMessage;
	type Err = Error;
	type Output = Option<(PresigningOutput<Secp256k1>, PresigningTranscript<Secp256k1>)>;

	fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<()> {
		let current_round = self.current_round();

		match msg.body {
			ProtocolMessage(M::Round1(m)) => {
				let store = self
					.round0_msgs
					.as_mut()
					.ok_or(Error::ReceivedOutOfOrderMessage { current_round, msg_round: 1 })?;
				store
					.push_msg(Msg { sender: msg.sender, receiver: msg.receiver, body: *m })
					.map_err(Error::HandleMessage)?;
				self.proceed_round(false)
			},
			ProtocolMessage(M::Round2(m)) => {
				let store = self
					.round1_msgs
					.as_mut()
					.ok_or(Error::ReceivedOutOfOrderMessage { current_round, msg_round: 2 })?;
				store
					.push_msg(Msg { sender: msg.sender, receiver: msg.receiver, body: *m })
					.map_err(Error::HandleMessage)?;
				self.proceed_round(false)
			},
			ProtocolMessage(M::Round3(m)) => {
				let store = self
					.round2_msgs
					.as_mut()
					.ok_or(Error::ReceivedOutOfOrderMessage { current_round, msg_round: 2 })?;
				store
					.push_msg(Msg { sender: msg.sender, receiver: msg.receiver, body: *m })
					.map_err(Error::HandleMessage)?;
				self.proceed_round(false)
			},
			ProtocolMessage(M::Round4(m)) => {
				let store = self
					.round3_msgs
					.as_mut()
					.ok_or(Error::ReceivedOutOfOrderMessage { current_round, msg_round: 2 })?;
				store
					.push_msg(Msg { sender: msg.sender, receiver: msg.receiver, body: *m })
					.map_err(Error::HandleMessage)?;
				self.proceed_round(false)
			},
		}
	}

	fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
		&mut self.msgs_queue
	}

	fn wants_to_proceed(&self) -> bool {
		let store1_wants_more = self.round0_msgs.as_ref().map(|s| s.wants_more()).unwrap_or(false);
		let store2_wants_more = self.round1_msgs.as_ref().map(|s| s.wants_more()).unwrap_or(false);
		let store3_wants_more = self.round2_msgs.as_ref().map(|s| s.wants_more()).unwrap_or(false);
		let store4_wants_more = self.round3_msgs.as_ref().map(|s| s.wants_more()).unwrap_or(false);

		match &self.round {
			R::Round0(_) => true,
			R::Round1(_) => !store1_wants_more,
			R::Round2(_) => !store2_wants_more,
			R::Round3(_) => !store3_wants_more,
			R::Round4(_) => !store4_wants_more,
			R::Final(_) | R::Gone => false,
		}
	}

	fn proceed(&mut self) -> Result<()> {
		self.proceed_round(true)
	}

	fn round_timeout(&self) -> Option<Duration> {
		None
	}

	fn round_timeout_reached(&mut self) -> Self::Err {
		panic!("no timeout was set")
	}

	fn is_finished(&self) -> bool {
		matches!(self.round, R::Final(_))
	}

	fn pick_output(&mut self) -> Option<Result<Self::Output>> {
		match self.round {
			R::Final(_) => (),
			R::Gone => return Some(Err(Error::DoublePickOutput)),
			_ => return None,
		}

		match replace(&mut self.round, R::Gone) {
			R::Final(result) => Some(Ok(*result)),
			_ => unreachable!("guaranteed by match expression above"),
		}
	}

	fn current_round(&self) -> u16 {
		match &self.round {
			R::Round0(_) => 0,
			R::Round1(_) => 1,
			R::Round2(_) => 2,
			R::Round3(_) => 3,
			R::Round4(_) => 4,
			R::Final(_) | R::Gone => 5,
		}
	}

	fn total_rounds(&self) -> Option<u16> {
		Some(2)
	}

	fn party_ind(&self) -> u16 {
		self.party_i
	}

	fn parties(&self) -> u16 {
		self.party_n
	}
}

impl crate::traits::RoundBlame for PreSigning {
	fn round_blame(&self) -> (u16, Vec<u16>) {
		let store1_blame = self.round0_msgs.as_ref().map(|s| s.blame()).unwrap_or_default();
		let store2_blame = self.round1_msgs.as_ref().map(|s| s.blame()).unwrap_or_default();
		let store3_blame = self.round2_msgs.as_ref().map(|s| s.blame()).unwrap_or_default();
		let store4_blame = self.round3_msgs.as_ref().map(|s| s.blame()).unwrap_or_default();

		let default = (0, vec![]);
		match &self.round {
			R::Round0(_) => default,
			R::Round1(_) => store1_blame,
			R::Round2(_) => store2_blame,
			R::Round3(_) => store3_blame,
			R::Round4(_) => store4_blame,
			R::Final(_) | R::Gone => default,
		}
	}
}

impl fmt::Debug for PreSigning {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let current_round = match &self.round {
			R::Round0(_) => "0",
			R::Round1(_) => "1",
			R::Round2(_) => "2",
			R::Round3(_) => "3",
			R::Round4(_) => "4",
			R::Final(_) => "[Final]",
			R::Gone => "[Gone]",
		};
		let round0_msgs = match self.round0_msgs.as_ref() {
			Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
			None => "[None]".into(),
		};
		let round1_msgs = match self.round1_msgs.as_ref() {
			Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
			None => "[None]".into(),
		};
		let _round2_msgs = match self.round2_msgs.as_ref() {
			Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
			None => "[None]".into(),
		};
		let _round3_msgs = match self.round3_msgs.as_ref() {
			Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
			None => "[None]".into(),
		};
		write!(
			f,
			"{{Key refresh at round={} round0_msgs={} round1_msgs={} queue=[len={}]}}",
			current_round,
			round0_msgs,
			round1_msgs,
			self.msgs_queue.len()
		)
	}
}

// Rounds
enum R {
	Round0(Box<Round0>),
	Round1(Box<Round1>),
	Round2(Box<Round2>),
	Round3(Box<Round3>),
	Round4(Box<Round4>),
	Final(Box<Option<(PresigningOutput<Secp256k1>, PresigningTranscript<Secp256k1>)>>),
	Gone,
}

// Messages

/// Protocol message which parties send on wire
///
/// Hides actual messages structure so it could be changed without breaking semver policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage(M);

#[derive(Debug, Clone, Serialize, Deserialize)]
enum M {
	Round1(Box<PreSigningP2PMessage1<Secp256k1>>),
	Round2(Box<PreSigningP2PMessage2<Secp256k1>>),
	Round3(Box<PreSigningP2PMessage3<Secp256k1>>),
	Round4(Box<Option<IdentifiableAbortBroadcastMessage<Secp256k1>>>),
}

// Error

type Result<T> = std::result::Result<T, Error>;

/// Error type of key refresh protocol
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
	/// Round proceeding resulted in error
	#[error("proceed round: {msg_round}")]
	ProceedRound { msg_round: usize },

	/// Too few parties (`n < 2`)
	#[error("at least 2 parties are required for keygen")]
	TooFewParties,
	/// Threshold value `t` is not in range `[1; n-1]`
	#[error("threshold is not in range [1; n-1]")]
	InvalidThreshold,
	/// Party index `i` is not in range `[1; n]`
	#[error("party index is not in range [1; n]")]
	InvalidPartyIndex,

	/// Received message didn't pass pre-validation
	#[error("received message didn't pass pre-validation: {0}")]
	HandleMessage(#[source] StoreErr),
	/// Received message which we didn't expect to receive now (e.g. message from previous round)
	#[error(
		"didn't expect to receive message from round {msg_round} (being at round {current_round})"
	)]
	ReceivedOutOfOrderMessage { current_round: u16, msg_round: u16 },
	/// [Keygen::pick_output] called twice
	#[error("pick_output called twice")]
	DoublePickOutput,

	/// Some internal assertions were failed, which is a bug
	#[doc(hidden)]
	#[error("internal error: {0:?}")]
	InternalError(InternalError),
}

impl IsCritical for Error {
	fn is_critical(&self) -> bool {
		true
	}
}

impl From<InternalError> for Error {
	fn from(err: InternalError) -> Self {
		Self::InternalError(err)
	}
}

mod private {
	#[derive(Debug)]
	#[non_exhaustive]
	pub enum InternalError {
		/// [Messages store](super::MessageStore) reported that it received all messages it wanted
		/// to receive, but refused to return message container
		RetrieveRoundMessages(super::StoreErr),
		#[doc(hidden)]
		StoreGone,
	}
}

#[cfg(test)]
pub mod test {
	use super::*;
	use crate::utilities::sha2::Sha256;
	use curv::{
		arithmetic::{
			traits::{Modulo, One, Samplable},
			Converter,
		},
		cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
		elliptic::curves::{Point, Scalar},
	};
	use fs_dkr::ring_pedersen_proof::RingPedersenStatement;
	use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{
		Keygen, LocalKey,
	};
	use round_based::dev::Simulation;
	use std::ops::Deref;

	fn simulate_keygen(t: u16, n: u16) -> Vec<LocalKey<Secp256k1>> {
		let mut simulation = Simulation::new();

		for i in 1..=n {
			simulation.add_party(Keygen::new(i, t, n).unwrap());
		}

		simulation.run().unwrap()
	}

	fn simulate_presign(
		inputs: Vec<(
			SSID<Secp256k1>,
			PreSigningSecrets,
			HashMap<u16, BigInt>, // S
			HashMap<u16, BigInt>, // T
			HashMap<u16, BigInt>, // N_hats
		)>,
		l: usize, // pre-signing index.
	) -> Vec<Option<(PresigningOutput<Secp256k1>, PresigningTranscript<Secp256k1>)>> {
		let mut simulation = Simulation::new();

		for (ssid, secrets, S, T, N_hats) in inputs {
			simulation.add_party(PreSigning::new(ssid, secrets, S, T, N_hats, l).unwrap());
		}

		simulation.run().unwrap()
	}

	pub fn extract_secret_key(local_keys: &[LocalKey<Secp256k1>]) -> Scalar<Secp256k1> {
		let secret_shares: Vec<Scalar<Secp256k1>> =
			local_keys.iter().map(|key| key.keys_linear.x_i.clone()).collect();
		local_keys[0]
			.vss_scheme
			.reconstruct(&(0..local_keys.len() as u16).collect::<Vec<u16>>(), &secret_shares)
	}

	pub fn extract_k(
		presign_outputs: &[Option<(
			PresigningOutput<Secp256k1>,
			PresigningTranscript<Secp256k1>,
		)>],
	) -> Scalar<Secp256k1> {
		let q = Scalar::<Secp256k1>::group_order();
		Scalar::<Secp256k1>::from_bigint(
			&presign_outputs
				.iter()
				.filter_map(|it| it.as_ref().map(|(output, _)| output.k_i.clone()))
				.fold(BigInt::from(0), |acc, x| BigInt::mod_add(&acc, &x, q)),
		)
	}

	// t = threshold, n = total number of parties, p = number of participants.
	// NOTE: Quorum size = t + 1.
	pub fn generate_parties_and_simulate_presign(
		t: u16,
		n: u16,
		p: u16,
	) -> (
		Vec<LocalKey<Secp256k1>>,
		Vec<SSID<Secp256k1>>,
		Vec<Option<(PresigningOutput<Secp256k1>, PresigningTranscript<Secp256k1>)>>,
	) {
		// Runs keygen simulation for test parameters.
		let keys = simulate_keygen(t, n);
		assert_eq!(keys.len(), n as usize);

		// Extracts and verifies the shared secret key.
		let sec_key = extract_secret_key(&keys);
		let pub_key = keys[0].public_key();
		assert_eq!(Point::<Secp256k1>::generator() * &sec_key, pub_key);

		// Verifies that transforming of x_i, which is a (t,n) share of x, into a (t,t+1) share
		// omega_i using an appropriate lagrangian coefficient lambda_{i,S} as defined by GG18 and
		// GG20 works.
		// Ref: https://eprint.iacr.org/2021/060.pdf (Section 1.2.8)
		// Ref: https://eprint.iacr.org/2019/114.pdf (Section 4.2)
		// Ref: https://eprint.iacr.org/2020/540.pdf (Section 3.2)
		let secret_shares: Vec<Scalar<Secp256k1>> =
			keys.iter().map(|key| key.keys_linear.x_i.clone()).collect();
		let omega_shares: Vec<Scalar<Secp256k1>> = keys[0..p as usize]
			.iter()
			.enumerate()
			.map(|(idx, key)| {
				let x_i = secret_shares[idx].clone();
				let lambda_i_s = VerifiableSS::<Secp256k1, Sha256>::map_share_to_new_params(
					&key.vss_scheme.parameters,
					key.i - 1,
					&(0..p).collect::<Vec<u16>>(),
				);
				lambda_i_s * x_i
			})
			.collect();
		let omega_sec_key = omega_shares.iter().fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + x);
		assert_eq!(omega_sec_key, sec_key);

		// Generates auxiliary "ring" Pedersen parameters for all participants.
		let mut aux_ring_pedersen_n_hat_values = HashMap::with_capacity(keys.len());
		let mut aux_ring_pedersen_s_values = HashMap::with_capacity(keys.len());
		let mut aux_ring_pedersen_t_values = HashMap::with_capacity(keys.len());
		for idx in 1..=p {
			let (ring_pedersen_params, _) = RingPedersenStatement::<Secp256k1, Sha256>::generate();
			aux_ring_pedersen_n_hat_values.insert(idx, ring_pedersen_params.N);
			aux_ring_pedersen_s_values.insert(idx, ring_pedersen_params.S);
			aux_ring_pedersen_t_values.insert(idx, ring_pedersen_params.T);
		}

		// Creates pre-signing inputs and auxiliary parameters for ZK proofs.
		let generator = Point::<Secp256k1>::generator().to_point();
		let group_order = Scalar::<Secp256k1>::group_order();
		let party_indices: Vec<u16> = (1..=p).collect();
		let inputs: Vec<(
			SSID<Secp256k1>,
			PreSigningSecrets,
			HashMap<u16, BigInt>, // S
			HashMap<u16, BigInt>, // T
			HashMap<u16, BigInt>, // N_hats
		)> = keys[0..p as usize]
			.iter()
			.map(|key| {
				// Creates SSID and pre-signing secrets.
				// We already have Paillier keys from GG20 keygen or FS-DKR so we just reuse them.
				let paillier_ek = key.paillier_key_vec[key.i as usize - 1].clone();
				let paillier_dk = key.paillier_dk.clone();
				// Composes SSID.
				// See Figure 6, Round 1.
				// Ref: <https://eprint.iacr.org/2021/060.pdf>.
				let phi = (&paillier_dk.p - BigInt::one()) * (&paillier_dk.q - BigInt::one());
				let r = BigInt::sample_below(&paillier_ek.n);
				let lambda = BigInt::sample_below(&phi);
				let t = BigInt::mod_pow(&r, &BigInt::from(2), &paillier_ek.n);
				let s = BigInt::mod_pow(&t, &lambda, &paillier_ek.n);
				let ssid = SSID {
					g: generator.clone(),
					q: group_order.clone(),
					P: party_indices.clone(),
					rid: BigInt::strict_sample(256).to_bytes().try_into().unwrap(),
					X: key.clone(),
					Y: None, // Y is not needed for 4-round signing.
					N: paillier_ek.n.clone(),
					S: s,
					T: t,
				};
				// Composes pre-signing secrets.
				let pre_sign_secrets = PreSigningSecrets {
					x_i: BigInt::from_bytes(key.keys_linear.x_i.to_bytes().deref()),
					y_i: None, // Y is not needed for 4-round signing.
					ek: paillier_ek,
					dk: paillier_dk,
				};

				(
					ssid,
					pre_sign_secrets,
					aux_ring_pedersen_s_values.clone(),
					aux_ring_pedersen_t_values.clone(),
					aux_ring_pedersen_n_hat_values.clone(),
				)
			})
			.collect();
		let ssids = inputs.iter().map(|(ssid, ..)| ssid.clone()).collect();

		// Runs pre-signing simulation for test parameters and verifies the outputs.
		let outputs = simulate_presign(inputs, 1);
		// Verifies that r, the x projection of R = g^k-1 is computed correctly.
		let q = Scalar::<Secp256k1>::group_order();
		let r_dist = outputs[0].as_ref().unwrap().0.R.x_coord().unwrap();
		let k = extract_k(&outputs);
		let r_direct = (Point::<Secp256k1>::generator() * k.invert().unwrap()).x_coord().unwrap();
		assert_eq!(r_dist, r_direct);
		// Verifies that chi_i are additive shares of kx.
		let k_x = &k * &sec_key;
		let chi_i_sum = Scalar::<Secp256k1>::from_bigint(
			&outputs
				.iter()
				.filter_map(|it| it.as_ref().map(|(output, _)| output.chi_i.clone()))
				.fold(BigInt::from(0), |acc, x| BigInt::mod_add(&acc, &x, q)),
		);
		assert_eq!(k_x, chi_i_sum);

		// Returns generated local keys, SSIDs and pre-signing outputs.
		(keys, ssids, outputs)
	}

	// All parties (2/2 pre-signing).
	#[test]
	fn presign_all_parties_works() {
		generate_parties_and_simulate_presign(1, 2, 2);
	}

	// Threshold pre-signing (subset of parties) - (3/4 pre-signing).
	#[test]
	fn presign_threshold_works() {
		generate_parties_and_simulate_presign(2, 4, 3);
	}
}
