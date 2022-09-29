use crate::refresh::rounds::{Round0, Round1, Round2};

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