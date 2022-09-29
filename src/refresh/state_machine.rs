use crate::keygen::state_machine::Error;
use crate::refresh::rounds::{Round0, Round1, Round2};
use thiserror::Error;

pub struct KeyRefresh {
    // Current round
    round: R,

    // Messages
    round0_msgs: Option<Store<BroadcastMsgs<Option<JoinMessage>>>>,
    round1_msgs:
        Option<Store<BroadcastMsgs<Option<FsDkrResult<RefreshMessage<Secp256k1, Sha256>>>>>>,

    // Message queue
    msgs_queue: Vec<Msg<ProtocolMessage>>,
}

impl KeyRefresh {
    pub fn new(local_key_option: Option<LocalKey<Secp256k1>>, t: u16, n: u16) -> Result<Self> {
        if n < 2 {
            return Err(Error::TooFewParties);
        }
        if t == 0 || t >= n {
            return Err(Error::InvalidThreshold);
        }
        let mut state = Self {
            round: R::Round0(Round0 {
                local_key_option,
                t,
                n,
            }),

            round0_msgs: Some(Round1::expects_messages(i, n)),
            round1_msgs: Some(Round2::expects_messages(i, n)),

            msgs_queue: vec![],
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
        let store1_wants_more = self
            .round0_msgs
            .as_ref()
            .map(|s| s.wants_more())
            .unwrap_or(false);
        let store2wants_more = self
            .round1_msgs
            .as_ref()
            .map(|s| s.wants_more())
            .unwrap_or(false);

        let next_state: R;

        let try_again: bool = match replace(&mut self.round, R::Gone) {
            R::Round0(round) if !round.is_expensive() || may_block => {
                next_state = round
                    .proceed(self.gmap_queue(M::Round1))
                    .map(R::Round1)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ R::Round0(_) => {
                next_state = s;
                false
            }
            R::Round1(round) if !store1_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.round0_msgs.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveRoundMessages)?;
                next_state = round
                    .proceed(msgs, self.gmap_queue(M::Round2))
                    .map(R::Round2)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ R::Round1(_) => {
                next_state = s;
                false
            }
            R::Round2(round) if !store2_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.round1_msgs.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveRoundMessages)?;
                next_state = round
                    .proceed(msgs)
                    .map(R::Final)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ R::Round2(_) => {
                next_state = s;
                false
            }
        };
        self.round = next_state;
        if try_again {
            self.proceed_round(may_block)
        } else {
            Ok(())
        }
    }
}

impl StateMachine for KeyRefresh {
    type MessageBody = ProtocolMessage;
    type Err = Error;
    type Output = LocalKey<Secp256k1>;

    fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<()> {
        let current_round = self.current_round();

        match msg.body {
            ProtocolMessage(M::Round1(m)) => {
                let store = self
                    .round0_msgs
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 1,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
                self.proceed_round(false)
            }
            ProtocolMessage(M::Round2(m)) => {
                let store = self
                    .round1_msgs
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
                self.proceed_round(false)
            }
        }
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        &mut self.msgs_queue
    }

    fn wants_to_proceed(&self) -> bool {
        let store1_wants_more = self
            .round0_msgs
            .as_ref()
            .map(|s| s.wants_more())
            .unwrap_or(false);
        let store2_wants_more = self
            .round1_msgs
            .as_ref()
            .map(|s| s.wants_more())
            .unwrap_or(false);

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

impl crate::traits::RoundBlame for Keygen {
    fn round_blame(&self) -> (u16, Vec<u16>) {
        let store1_blame = self
            .round0_msgs
            .as_ref()
            .map(|s| s.blame())
            .unwrap_or_default();
        let store2_blame = self
            .round1_msgs
            .as_ref()
            .map(|s| s.blame())
            .unwrap_or_default();

        let default = (0, vec![]);
        match &self.round {
            R::Round0(_) => default,
            R::Round1(_) => store1_blame,
            R::Round2(_) => store2_blame,
            R::Final(_) | R::Gone => default,
        }
    }
}

impl fmt::Debug for KeyRefresh {
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
            "{{Keygen at round={} msgs1={} msgs2={} msgs3={} msgs4={} queue=[len={}]}}",
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
    Round2(Round2),
    Final(LocalKey<Secp256k1>),
    Gone,
}

// Messages

/// Protocol message which parties send on wire
///
/// Hides actual messages structure so it could be changed without breaking semver policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage(M);

#[derive(Clone, Debug, Serialize, Deserialize)]
enum M {
    Round1(Option<JoinMessage>),
    Round2(Option<FsDkrResult<RefreshMessage<Secp256k1, Sha256>>>),
}

#[cfg(test)]
pub mod test {
    use round_based::dev::Simulation;

    use super::*;

    pub fn simulate_keygen(t: u16, n: u16) -> Vec<LocalKey<Secp256k1>> {
        let mut simulation = Simulation::new();
        simulation.enable_benchmarks(true);

        for i in 1..=n {
            simulation.add_party(Keygen::new(i, t, n).unwrap());
        }

        let keys = simulation.run().unwrap();

        println!("Benchmark results:");
        println!("{:#?}", simulation.benchmark_results().unwrap());

        keys
    }

    #[test]
    fn simulate_keygen_t1_n2() {
        simulate_keygen(1, 2);
    }

    #[test]
    fn simulate_keygen_t1_n3() {
        simulate_keygen(1, 3);
    }

    #[test]
    fn simulate_keygen_t2_n3() {
        simulate_keygen(2, 3);
    }
}
