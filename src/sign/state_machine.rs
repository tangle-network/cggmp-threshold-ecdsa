use crate::presign::{PresigningOutput, PresigningTranscript, SSID};

use super::{
	rounds::{Round0, Round1, Round2},
	SigningBroadcastMessage1, SigningIdentifiableAbortMessage, SigningOutput,
};

use curv::{
	arithmetic::{traits::*, Modulo, Samplable},
	cryptographic_primitives::hashing::{Digest, DigestExt},
	elliptic::curves::{Curve, Point, Scalar, Secp256k1},
	BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use private::InternalError;
use round_based::{
	containers::{
		push::{Push, PushExt},
		BroadcastMsgs, MessageContainer, MessageStore, P2PMsgs, Store, StoreErr,
	},
	IsCritical, Msg, StateMachine,
};
use std::{collections::HashMap, fmt, mem::replace, time::Duration};
use thiserror::Error;

// NOTE: This is a hack since in the 1st round we will need to broadcast and send P2P
// messages, but the round-based library doesn't support this. So we will use the
// `P2PMsgs` to send all the data we need peers to receive.
// FIXME: If we re-design `round-based-traits` to support sending 2 types of messages
// in the same round, we can remove this hack.
pub type Round0Messages = Store<BroadcastMsgs<SigningBroadcastMessage1<Secp256k1>>>;
pub type Round1Messages = Store<BroadcastMsgs<Option<SigningIdentifiableAbortMessage<Secp256k1>>>>;

pub struct Signing {
	// Current round
	round: R,

	// Messages
	round0_msgs: Option<Round0Messages>,
	round1_msgs: Option<Round1Messages>,

	// Message queue
	msgs_queue: Vec<Msg<ProtocolMessage>>,
	party_i: u16,
	party_n: u16,
}

impl Signing {
	pub fn new(
		ssid: SSID<Secp256k1>,
		l: usize, // This is the number of presignings to run in parallel
		m: BigInt,
		presigning_data: HashMap<
			u16,
			(PresigningOutput<Secp256k1>, PresigningTranscript<Secp256k1>),
		>,
	) -> Result<Self> {
		let n = ssid.P.len() as u16;
		let i = ssid.X.i;
		if n < 2 {
			return Err(Error::TooFewParties)
		}

		let mut state = Self {
			round: R::Round0(Round0 { ssid, l, m, presigning_data }),

			round0_msgs: Some(Round1::expects_messages(i, n)),
			round1_msgs: Some(Round2::expects_messages(i, n)),

			msgs_queue: vec![],

			party_i: i,
			party_n: n,
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

		let next_state: R;

		let try_again: bool = match replace(&mut self.round, R::Gone) {
			R::Round0(round) if !round.is_expensive() || may_block => {
				next_state = round
					.proceed(self.gmap_queue(M::Round1))
					.map(R::Round1)
					.map_err(|e| Error::ProceedRound { msg_round: 0 })?;
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
					.map_err(|e| Error::ProceedRound { msg_round: 1 })?;
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
					.proceed(msgs)
					.map(R::Final)
					.map_err(|e| Error::ProceedRound { msg_round: 2 })?;
				true
			},
			s @ R::Round2(_) => {
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

impl StateMachine for Signing {
	type MessageBody = ProtocolMessage;
	type Err = Error;
	type Output = Option<SigningOutput<Secp256k1>>;

	fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<()> {
		let current_round = self.current_round();

		match msg.body {
			ProtocolMessage(M::Round1(m)) => {
				let store = self
					.round0_msgs
					.as_mut()
					.ok_or(Error::ReceivedOutOfOrderMessage { current_round, msg_round: 1 })?;
				store
					.push_msg(Msg { sender: msg.sender, receiver: msg.receiver, body: m })
					.map_err(Error::HandleMessage)?;
				self.proceed_round(false)
			},
			ProtocolMessage(M::Round2(m)) => {
				let store = self
					.round1_msgs
					.as_mut()
					.ok_or(Error::ReceivedOutOfOrderMessage { current_round, msg_round: 2 })?;
				store
					.push_msg(Msg { sender: msg.sender, receiver: msg.receiver, body: m })
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

		match &self.round {
			R::Round0(_) => true,
			R::Round1(_) => !store1_wants_more,
			R::Round2(_) => !store2_wants_more,
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
			R::Final(result) => Some(Ok(result)),
			_ => unreachable!("guaranteed by match expression above"),
		}
	}

	fn current_round(&self) -> u16 {
		match &self.round {
			R::Round0(_) => 0,
			R::Round1(_) => 1,
			R::Round2(_) => 2,
			R::Final(_) | R::Gone => 3,
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

impl crate::traits::RoundBlame for Signing {
	fn round_blame(&self) -> (u16, Vec<u16>) {
		let store1_blame = self.round0_msgs.as_ref().map(|s| s.blame()).unwrap_or_default();
		let store2_blame = self.round1_msgs.as_ref().map(|s| s.blame()).unwrap_or_default();

		let default = (0, vec![]);
		match &self.round {
			R::Round0(_) => default,
			R::Round1(_) => store1_blame,
			R::Round2(_) => store2_blame,
			R::Final(_) | R::Gone => default,
		}
	}
}

impl fmt::Debug for Signing {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let current_round = match &self.round {
			R::Round0(_) => "0",
			R::Round1(_) => "1",
			R::Round2(_) => "2",
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
	Round0(Round0),
	Round1(Round1),
	Round2(Box<Round2>),
	Final(Option<SigningOutput<Secp256k1>>),
	Gone,
}

// Messages

/// Protocol message which parties send on wire
///
/// Hides actual messages structure so it could be changed without breaking semver policy.
#[derive(Debug, Clone)]
pub struct ProtocolMessage(M);

#[derive(Debug, Clone)]
enum M {
	Round1(SigningBroadcastMessage1<Secp256k1>),
	Round2(Option<SigningIdentifiableAbortMessage<Secp256k1>>),
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

pub mod test {}
