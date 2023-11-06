//! Message definitions for new parties that can join the protocol
//! Key points about a new party joining the refresh protocol:
//! * A new party wants to join, broadcasting a paillier ek, correctness of the
//!   ek generation,
//! dlog statements and dlog proofs.
//! * All the existing parties receives the join message. We assume for now that
//!   everyone accepts
//! the new party. All parties pick an index and add the new ek to their
//! LocalKey at the given index.
//! * The party index of the new party is transmitted back to the joining party
//!   offchannel (it's
//! public information).
//! * All the existing parties enter the distribute phase, in which they start
//!   refreshing their
//! existing keys taking into the account the join messages that they received.
//! ** All parties (including new ones) collect the refresh messages and the
//! join messages.

use crate::{
    error::{FsDkrError, FsDkrResult},
    refresh_message::RefreshMessage,
};
use curv::{
    arithmetic::Zero,
    cryptographic_primitives::{
        hashing::Digest,
        secret_sharing::feldman_vss::{ShamirSecretSharing, VerifiableSS},
    },
    elliptic::curves::{Curve, Point, Scalar},
    BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
    party_i::{Keys, SharedKeys},
    state_machine::keygen::LocalKey,
};
use paillier::{Decrypt, EncryptionKey, Paillier};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug};
use zk_paillier::zkproofs::NiCorrectKeyProof;

use crate::ring_pedersen_proof::{RingPedersenProof, RingPedersenStatement};
use tss_core::utilities::generate_safe_h1_h2_N_tilde;
use tss_core::zkproof::prm::{PiPrmProof, PiPrmStatement, PiPrmWitness};

/// Message used by new parties to join the protocol.
#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(bound = "E: Curve, H: Digest + Clone")]
pub struct JoinMessage<E: Curve, H: Digest + Clone, const M: usize> {
    pub(crate) ek: EncryptionKey,
    pub(crate) dk_correctness_proof: NiCorrectKeyProof,
    pub(crate) party_index: Option<u16>,
    pub(crate) dlog_statement: PiPrmStatement,
    pub(crate) composite_dlog_proof_base_h1: PiPrmProof,
    pub(crate) composite_dlog_proof_base_h2: PiPrmProof,
    pub(crate) ring_pedersen_statement: RingPedersenStatement<E, H>,
    pub(crate) ring_pedersen_proof: RingPedersenProof<E, H, M>,
}

/// Generates the DlogStatement and CompositeProofs using the parameters
/// generated by [generate_h1_h2_n_tilde]
fn generate_dlog_statement_proofs(
) -> FsDkrResult<(PiPrmStatement, PiPrmProof, PiPrmProof)> {
    let (n_tilde, h1, h2, xhi, xhi_inv, phi) = generate_safe_h1_h2_N_tilde();

    let dlog_statement_base_h1 = PiPrmStatement {
        modulus: n_tilde.clone(),
        base: h1.clone(),
        value: h2.clone(),
    };
    let dlog_witness_base_h1 = PiPrmWitness {
        exponent: xhi,
        totient: phi.clone(),
    };

    let dlog_statement_base_h2 = PiPrmStatement {
        modulus: n_tilde,
        base: h2,
        value: h1,
    };
    let dlog_witness_base_h2 = PiPrmWitness {
        exponent: xhi_inv,
        totient: phi.clone(),
    };

    let composite_dlog_proof_base_h1 =
        PiPrmProof::prove(&dlog_statement_base_h1, &dlog_witness_base_h1)
            .map_err(|_| FsDkrError::CompositeDLogProofGeneration)?;
    let composite_dlog_proof_base_h2 =
        PiPrmProof::prove(&dlog_statement_base_h2, &dlog_witness_base_h2)
            .map_err(|_| FsDkrError::CompositeDLogProofGeneration)?;

    Ok((
        dlog_statement_base_h1,
        composite_dlog_proof_base_h1,
        composite_dlog_proof_base_h2,
    ))
}

impl<E: Curve, H: Digest + Clone, const M: usize> JoinMessage<E, H, M> {
    pub fn set_party_index(&mut self, new_party_index: u16) {
        self.party_index = Some(new_party_index);
    }
    /// The distribute phase for a new party. This distribute phase has to
    /// happen before the existing parties distribute. Calling this function
    /// will generate a JoinMessage and a pair of Paillier [Keys] that are
    /// going to be used when generating the [LocalKey].
    pub fn distribute() -> FsDkrResult<(Self, Keys)> {
        let paillier_key_pair = Keys::create(0);
        let (
            dlog_statement,
            composite_dlog_proof_base_h1,
            composite_dlog_proof_base_h2,
        ) = generate_dlog_statement_proofs()?;

        let (ring_pedersen_statement, ring_pedersen_witness) =
            RingPedersenStatement::generate();

        let ring_pedersen_proof = RingPedersenProof::prove(
            &ring_pedersen_witness,
            &ring_pedersen_statement,
        );

        let join_message = JoinMessage {
            // in a join message, we only care about the ek and the correctness
            // proof
            ek: paillier_key_pair.ek.clone(),
            dk_correctness_proof: NiCorrectKeyProof::proof(
                &paillier_key_pair.dk,
                None,
            ),
            dlog_statement,
            composite_dlog_proof_base_h1,
            composite_dlog_proof_base_h2,
            ring_pedersen_statement,
            ring_pedersen_proof,
            party_index: None,
        };

        Ok((join_message, paillier_key_pair))
    }
    /// Returns the party index if it has been assigned one, throws
    /// [FsDkrError::NewPartyUnassignedIndexError] otherwise
    pub fn get_party_index(&self) -> FsDkrResult<u16> {
        self.party_index
            .ok_or(FsDkrError::NewPartyUnassignedIndexError)
    }

    /// Collect phase of the protocol. Compared to the
    /// [RefreshMessage::collect], this has to be tailored for a sent
    /// JoinMessage on which we assigned party_index. In this collect, a
    /// [LocalKey] is filled with the information provided by the
    /// [RefreshMessage]s from the other parties and the other join messages
    /// (multiple parties can be added/replaced at once).
    pub fn collect(
        &self,
        refresh_messages: &[RefreshMessage<E, H, M>],
        paillier_key: Keys,
        join_messages: &[JoinMessage<E, H, M>],
        new_t: u16,
        new_n: u16,
        current_t: u16,
    ) -> FsDkrResult<LocalKey<E>> {
        RefreshMessage::validate_collect(refresh_messages, current_t, new_n)?;

        for refresh_message in refresh_messages.iter() {
            RingPedersenProof::verify(
                &refresh_message.ring_pedersen_proof,
                &refresh_message.ring_pedersen_statement,
            )
            .map_err(|_| {
                FsDkrError::RingPedersenProofValidation {
                    party_index: refresh_message.party_index,
                }
            })?;
        }

        for join_message in join_messages.iter() {
            RingPedersenProof::verify(
                &join_message.ring_pedersen_proof,
                &join_message.ring_pedersen_statement,
            )
            .map_err(|e| {
                if let Some(party_index) = join_message.party_index {
                    FsDkrError::RingPedersenProofValidation { party_index }
                } else {
                    e
                }
            })?;
        }

        // check if a party_index has been assigned to the current party
        let party_index = self.get_party_index()?;

        // check if a party_index has been assigned to all other new parties
        // TODO: Check if no party_index collision exists
        for join_message in join_messages.iter() {
            join_message.get_party_index()?;
        }

        let parameters = ShamirSecretSharing {
            threshold: new_t,
            share_count: new_n,
        };

        // generate a new share, the details can be found here https://hackmd.io/@omershlo/Hy1jBo6JY.
        let (cipher_text_sum, li_vec) = RefreshMessage::get_ciphertext_sum(
            refresh_messages,
            party_index,
            &parameters,
            &paillier_key.ek,
        );
        let new_share = Paillier::decrypt(&paillier_key.dk, cipher_text_sum)
            .0
            .into_owned();

        let new_share_fe: Scalar<E> = Scalar::<E>::from(&new_share);
        let paillier_dk = paillier_key.dk.clone();
        let key_linear_x_i = new_share_fe.clone();
        let key_linear_y = Point::<E>::generator() * new_share_fe.clone();
        let keys_linear = SharedKeys {
            x_i: key_linear_x_i,
            y: key_linear_y,
        };
        let mut pk_vec: Vec<_> = (0..new_n as usize)
            .map(|i| {
                refresh_messages[0].points_committed_vec[i].clone()
                    * li_vec[0].clone()
            })
            .collect();

        #[allow(clippy::needless_range_loop)]
        for i in 0..new_n as usize {
            for j in 1..refresh_messages.len() {
                pk_vec[i] = pk_vec[i].clone()
                    + refresh_messages[j].points_committed_vec[i].clone()
                        * li_vec[j].clone();
            }
        }

        // check what parties are assigned in the current rotation and associate
        // their paillier ek to each available party index.

        let available_parties: HashMap<u16, &EncryptionKey> = refresh_messages
            .iter()
            .map(|msg| (msg.party_index, &msg.ek))
            .chain(std::iter::once((party_index, &paillier_key.ek)))
            .chain(join_messages.iter().map(|join_message| {
                (join_message.party_index.unwrap(), &join_message.ek)
            }))
            .collect();

        // TODO: submit the statement the dlog proof as well!
        // check what parties are assigned in the current rotation and associate
        // their DLogStatements and check their CompositeDlogProofs.
        let available_h1_h2_ntilde_vec: HashMap<u16, &PiPrmStatement> =
            refresh_messages
                .iter()
                .map(|msg| (msg.party_index, &msg.dlog_statement))
                .chain(std::iter::once((party_index, &self.dlog_statement)))
                .chain(join_messages.iter().map(|join_message| {
                    (
                        join_message.party_index.unwrap(),
                        &join_message.dlog_statement,
                    )
                }))
                .collect();

        // generate the paillier public key vec needed for the LocalKey
        // generation.
        let paillier_key_vec: Vec<EncryptionKey> = (1..new_n + 1)
            .map(|party| {
                let ek = available_parties.get(&party);
                match ek {
                    None => EncryptionKey {
                        n: BigInt::zero(),
                        nn: BigInt::zero(),
                    },
                    Some(key) => (*key).clone(),
                }
            })
            .collect();
        // generate the DLogStatement vec needed for the LocalKey generation.
        let mut h1_h2_ntilde_vec: Vec<PiPrmStatement> =
            Vec::with_capacity(new_n as usize);
        for party in 1..new_n + 1 {
            let statement = available_h1_h2_ntilde_vec.get(&party);
            h1_h2_ntilde_vec.push(match statement {
                None => generate_dlog_statement_proofs()?.0,
                Some(dlog_statement) => (*dlog_statement).clone(),
            });
        }

        // check if all the existing parties submitted the same public key. If
        // they differ, abort. TODO: this should be verifiable?
        for refresh_message in refresh_messages.iter() {
            if refresh_message.public_key != refresh_messages[0].public_key {
                return Err(FsDkrError::BroadcastedPublicKeyError);
            }
        }

        // generate the vss_scheme for the LocalKey
        let (vss_scheme, _) =
            VerifiableSS::<E, sha2::Sha256>::share(new_t, new_n, &new_share_fe);
        // TODO: secret cleanup might be needed.

        let local_key = LocalKey {
            paillier_dk,
            pk_vec,
            keys_linear,
            paillier_key_vec,
            y_sum_s: refresh_messages[0].public_key.clone(),
            h1_h2_n_tilde_vec: h1_h2_ntilde_vec,
            vss_scheme,
            i: party_index,
            t: new_t,
            n: new_n,
        };

        Ok(local_key)
    }
}
