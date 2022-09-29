use crate::refresh::rounds::{Round0, Round1, Round2};
use thiserror::Error;

pub struct KeyRefresh {
    // Current round
    round: R,

    // Messages 
    round0_msgs: Option<Store<BroadcastMsgs<Option<JoinMessage>>>>,
    round1_msgs: Option<Store<BroadcastMsgs<Option<FsDkrResult<RefreshMessage<Secp256k1, Sha256>>>>>>,

    // Message queue
    msgs_queue: Vec<Msg<ProtocolMessage>>,

    party_i: usize,
    party_n: usize,
}


impl KeyRefresh {
}

impl StateMachine for KeyRefresh {
    type MessageBody = ProtocolMessage;
    type Err = Error;
    type Output = LocalKey<Secp256k1>;

    fn handle_incoming() {}

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        &mut self.msgs_queue
    }

    fn wants_to_proceed(){}

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

