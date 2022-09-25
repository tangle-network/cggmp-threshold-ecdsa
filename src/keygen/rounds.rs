use curv::arithmetic::Converter;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};
use curv::BigInt;
use sha2::Sha256;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use paillier::Paillier;
use paillier::{Decrypt, Encrypt};
use paillier::{EncryptionKey, RawCiphertext, RawPlaintext};
use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, MessageStore, P2PMsgs, P2PMsgsStore, Store};
use round_based::Msg;
use zk_paillier::zkproofs::DLogStatement;

use crate::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys,
};
use crate::{ErrorType};

pub struct Round0 {
    pub party_i: u16,
    pub t: u16,
    pub n: u16,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<Vec<u8>>>,
    {
        let party_keys = Keys::create(self.party_i as usize);
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: vec![],
        });
        Ok(Round1 {
            keys: party_keys,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round1 {
    keys: Keys,
    party_i: u16,
    t: u16,
    n: u16,
}

impl Round1 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round2>
    where
        O: Push<Msg<Vec<u8>>>,
    {
        let party_keys = Keys::create(self.party_i as usize);
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: vec![],
        });
        Ok(Round2 {
            keys: party_keys,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round2 {
    keys: Keys,
    party_i: u16,
    t: u16,
    n: u16,
}

impl Round2 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round3>
    where
        O: Push<Msg<Vec<u8>>>,
    {
        let party_keys = Keys::create(self.party_i as usize);
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: vec![],
        });
        Ok(Round3 {
            keys: party_keys,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round3 {
    keys: Keys,
    party_i: u16,
    t: u16,
    n: u16,
}

impl Round3 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round4>
    where
        O: Push<Msg<Vec<u8>>>,
    {
        let party_keys = Keys::create(self.party_i as usize);
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: vec![],
        });
        Ok(Round4 {
            keys: party_keys,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round4 {
    keys: Keys,
    party_i: u16,
    t: u16,
    n: u16,
}

impl Round4 {
    pub fn proceed(
        self,
        input: BroadcastMsgs<DLogProof<Secp256k1, Sha256>>,
    ) -> Result<Option<LocalKey<Secp256k1>>> {
        Ok(None)
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<DLogProof<Secp256k1, Sha256>>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

/// Local secret obtained by party after [keygen](super::Keygen) protocol is completed
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LocalKey<E: Curve> {
    pub paillier_dk: paillier::DecryptionKey,
    pub pk_vec: Vec<Point<E>>,
    pub keys_linear: crate::party_i::SharedKeys,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub y_sum_s: Point<E>,
    pub h1_h2_n_tilde_vec: Vec<DLogStatement>,
    pub vss_scheme: VerifiableSS<E>,
    pub i: u16,
    pub t: u16,
    pub n: u16,
}

impl LocalKey<Secp256k1> {
    /// Public key of secret shared between parties
    pub fn public_key(&self) -> Point<Secp256k1> {
        self.y_sum_s.clone()
    }
}

// Errors

type Result<T> = std::result::Result<T, ProceedError>;

/// Proceeding protocol error
///
/// Subset of [keygen errors](enum@super::Error) that can occur at protocol proceeding (i.e. after
/// every message was received and pre-validated).
#[derive(Debug, Error)]
pub enum ProceedError {
    #[error("round 2: verify commitments: {0:?}")]
    Round2VerifyCommitments(ErrorType),
    #[error("round 3: verify vss construction: {0:?}")]
    Round3VerifyVssConstruct(ErrorType),
    #[error("round 4: verify dlog proof: {0:?}")]
    Round4VerifyDLogProof(ErrorType),
}
