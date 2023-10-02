#![allow(dead_code)]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::many_single_char_names))]
//! FS-DKR is a protocol for rotation of threshold ECDSA keys.
//!
//! We use standard proactive security assumptions. The protocol will be run
//! by $n$ parties. We assume honest majority, that is, number of corruptions is $t<=n/2$.
//! The adversary is malicious, and rushing. For communication, the parties have access
//! to a broadcast channel (can be implemented via a bulletin board). For threshold ECDSA,
//! we focus on GG20 protocol, currently considered state of the art and most widely deployed
//! threshold ecdsa scheme (e.g. multi-party-ecdsa, tss-lib).
//!
//! Components of the library:
//!
//! * [refresh_message]: crate::refresh_message
//!

pub mod add_party_message;
pub mod error;
pub mod range_proofs;
pub mod refresh_message;
pub mod ring_pedersen_proof;
pub mod zk_pdl_with_slack;

mod test;

pub const PAILLIER_KEY_SIZE: usize = 2048;
pub const M_SECURITY: usize = 256;
