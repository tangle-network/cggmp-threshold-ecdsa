use crate::{
	add_party_message::JoinMessage,
	error::{FsDkrError, FsDkrResult},
	range_proofs::AliceProof,
	zk_pdl_with_slack::{PDLwSlackProof, PDLwSlackStatement, PDLwSlackWitness},
};
use curv::{
	arithmetic::{BitManipulation, Samplable, Zero},
	cryptographic_primitives::{
		hashing::Digest,
		secret_sharing::feldman_vss::{ShamirSecretSharing, VerifiableSS},
	},
	elliptic::curves::{Curve, Point, Scalar},
	BigInt, HashChoice,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
pub use paillier::DecryptionKey;
use paillier::{
	Add, Decrypt, Encrypt, EncryptWithChosenRandomness, EncryptionKey, KeyGeneration, Mul,
	Paillier, Randomness, RawCiphertext, RawPlaintext,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, collections::HashMap, fmt::Debug};
use zeroize::Zeroize;
use zk_paillier::zkproofs::{NiCorrectKeyProof, SALT_STRING};
use tss_core::{
    utilities::generate_safe_h1_h2_N_tilde,
    zkproof::prm::{PiPrmStatement, PiPrmWitness, PiPrmProof},
};

// Everything here can be broadcasted
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "E: Curve, H: Digest + Clone")]
pub struct RefreshMessage<E: Curve, H: Digest + Clone> {
    pub(crate) old_party_index: u16,
    pub(crate) party_index: u16,
    pdl_proof_vec: Vec<PDLwSlackProof<E, H>>,
    range_proofs: Vec<AliceProof<E, H>>,
    coefficients_committed_vec: VerifiableSS<E, sha2::Sha256>,
    pub(crate) points_committed_vec: Vec<Point<E>>,
    points_encrypted_vec: Vec<BigInt>,
    dk_correctness_proof: NiCorrectKeyProof,
    pub(crate) dlog_statement: PiPrmStatement,
    pub(crate) ek: EncryptionKey,
    pub(crate) remove_party_indices: Vec<u16>,
    pub(crate) public_key: Point<E>,
    pub(crate) ring_pedersen_pi_prm_statement: PiPrmStatement,
    pub(crate) ring_pedersen_pi_prm_proof: PiPrmProof,
    #[serde(skip)]
    pub hash_choice: HashChoice<H>,
}

impl<E: Curve, H: Digest + Clone> RefreshMessage<E, H> {
    pub fn distribute(
        old_party_index: u16,
        local_key: &mut LocalKey<E>,
        new_t: u16,
        new_n: u16,
    ) -> FsDkrResult<(RefreshMessage<E, H>, DecryptionKey)> {
        assert!(new_t <= new_n / 2);
        let secret = local_key.keys_linear.x_i.clone();
        // secret share old key
        if new_n <= new_t {
            return Err(FsDkrError::NewPartyUnassignedIndexError);
        }
        let (vss_scheme, secret_shares) =
            VerifiableSS::<E, sha2::Sha256>::share(new_t, new_n, &secret);

        local_key.vss_scheme = vss_scheme.clone();

        // commit to points on the polynomial
        let points_committed_vec: Vec<_> = (0..secret_shares.len())
            .map(|i| Point::<E>::generator() * &secret_shares[i].clone())
            .collect();

        // encrypt points on the polynomial using Paillier keys
        let (points_encrypted_vec, randomness_vec): (Vec<_>, Vec<_>) = (0
            ..secret_shares.len())
            .map(|i| {
                let randomness =
                    BigInt::sample_below(&local_key.paillier_key_vec[i].n);
                let ciphertext = Paillier::encrypt_with_chosen_randomness(
                    &local_key.paillier_key_vec[i],
                    RawPlaintext::from(secret_shares[i].to_bigint()),
                    &Randomness::from(randomness.clone()),
                )
                .0
                .into_owned();
                (ciphertext, randomness)
            })
            .unzip();

        // generate PDL proofs for each {point_committed, point_encrypted} pair
        let pdl_proof_vec: Vec<_> = (0..secret_shares.len())
            .map(|i| {
                let witness = PDLwSlackWitness {
                    x: secret_shares[i].clone(),
                    r: randomness_vec[i].clone(),
                };
                let statement = PDLwSlackStatement {
                    ciphertext: points_encrypted_vec[i].clone(),
                    ek: local_key.paillier_key_vec[i].clone(),
                    Q: points_committed_vec[i].clone(),
                    G: Point::<E>::generator().to_point(),
                    h1: local_key.h1_h2_n_tilde_vec[i].base.clone(),
                    h2: local_key.h1_h2_n_tilde_vec[i].value.clone(),
                    N_tilde: local_key.h1_h2_n_tilde_vec[i].modulus.clone(),
                };
                PDLwSlackProof::prove(&witness, &statement)
            })
            .collect();

        let range_proofs = (0..secret_shares.len())
            .map(|i| {
                AliceProof::generate(
                    &secret_shares[i].to_bigint(),
                    &points_encrypted_vec[i],
                    &local_key.paillier_key_vec[i],
                    &local_key.h1_h2_n_tilde_vec[i],
                    &randomness_vec[i],
                )
            })
            .collect();

        let (ek, dk) =
            Paillier::keypair_with_modulus_size(crate::PAILLIER_KEY_SIZE)
                .keys();
        let dk_correctness_proof = NiCorrectKeyProof::proof(&dk, None);
        let (rpparam, rpwitness) = generate_safe_h1_h2_N_tilde();
        let pi_prm_statement = PiPrmStatement::from(&rpparam);
        let pi_prm_witness = PiPrmWitness::from(&rpwitness);
        let pi_prm_proof =
            PiPrmProof::prove(&pi_prm_statement, &pi_prm_witness)
                .map_err(|_| FsDkrError::RingPedersenProofError {})?;

        Ok((
            RefreshMessage {
                old_party_index,
                party_index: local_key.i,
                pdl_proof_vec,
                range_proofs,
                coefficients_committed_vec: vss_scheme,
                points_committed_vec,
                points_encrypted_vec,
                dk_correctness_proof,
                dlog_statement: local_key.h1_h2_n_tilde_vec
                    [(local_key.i - 1) as usize]
                    .clone(),
                ek,
                remove_party_indices: Vec::new(),
                public_key: local_key.y_sum_s.clone(),
                ring_pedersen_pi_prm_statement: pi_prm_statement,
                ring_pedersen_pi_prm_proof: pi_prm_proof,
                hash_choice: HashChoice::new(),
            },
            dk,
        ))
    }

    pub fn validate_collect(
        refresh_messages: &[Self],
        current_t: u16,
        new_n: u16,
    ) -> FsDkrResult<()> {
        // check we got at least current threshold t + 1 refresh messages
        // (i.e a quorum of existing parties has sent refresh messages).
        if refresh_messages.len() <= current_t.into() {
            return Err(FsDkrError::PartiesThresholdViolation {
                threshold: current_t,
                refreshed_keys: refresh_messages.len(),
            });
        }

        // check all vectors are of same length
        let reference_len = refresh_messages[0].pdl_proof_vec.len();

        for (k, refresh_message) in refresh_messages.iter().enumerate() {
            let pdl_proof_len = refresh_message.pdl_proof_vec.len();
            let points_commited_len =
                refresh_message.points_committed_vec.len();
            let points_encrypted_len =
                refresh_message.points_encrypted_vec.len();

            if !(pdl_proof_len == reference_len
                && points_commited_len == reference_len
                && points_encrypted_len == reference_len)
            {
                return Err(FsDkrError::SizeMismatchError {
                    refresh_message_index: k,
                    pdl_proof_len,
                    points_commited_len,
                    points_encrypted_len,
                });
            }
        }

        for refresh_message in refresh_messages.iter() {
            for i in 0..new_n as usize {
                //TODO: we should handle the case of t<i<n
                if refresh_message
                    .coefficients_committed_vec
                    .validate_share_public(
                        &refresh_message.points_committed_vec[i],
                        i as u16 + 1,
                    )
                    .is_err()
                {
                    return Err(FsDkrError::PublicShareValidationError);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn get_ciphertext_sum<'a>(
        refresh_messages: &'a [Self],
        party_index: u16,
        parameters: &'a ShamirSecretSharing,
        ek: &'a EncryptionKey,
    ) -> (RawCiphertext<'a>, Vec<Scalar<E>>) {
        // we first homomorphically add all ciphertext encrypted using our
        // encryption key
        let indices: Vec<u16> = (0..refresh_messages.len())
            .map(|i| refresh_messages[i].old_party_index - 1)
            .collect();

        let ciphertext_vec: Vec<_> = refresh_messages
            .iter()
            .map(|msg| {
                msg.points_encrypted_vec[(party_index - 1) as usize].clone()
            })
            .collect();

        // optimization - one decryption
        let li_vec: Vec<_> = indices
            .iter()
            .map(|i| {
                VerifiableSS::<E, sha2::Sha256>::map_share_to_new_params(
                    parameters.clone().borrow(),
                    *i,
                    &indices,
                )
            })
            .collect();

        let ciphertext_vec_at_indices_mapped: Vec<_> = (0..indices.len())
            .map(|i| {
                Paillier::mul(
                    ek,
                    RawCiphertext::from(ciphertext_vec[i].clone()),
                    RawPlaintext::from(li_vec[i].to_bigint()),
                )
            })
            .collect();

        let ciphertext_sum = ciphertext_vec_at_indices_mapped.iter().fold(
            Paillier::encrypt(ek, RawPlaintext::from(BigInt::zero())),
            |acc, x| Paillier::add(ek, acc, x.clone()),
        );

        (ciphertext_sum, li_vec)
    }

    pub fn replace(
        new_parties: &[JoinMessage<E, H>],
        key: &mut LocalKey<E>,
        old_to_new_map: &HashMap<u16, u16>,
        new_t: u16,
        new_n: u16,
    ) -> FsDkrResult<(Self, DecryptionKey)> {
        let current_len = key.paillier_key_vec.len() as u16;
        let mut paillier_key_h1_h2_n_tilde_hash_map: HashMap<
            u16,
            (EncryptionKey, PiPrmStatement),
        > = HashMap::new();
        for old_party_index in old_to_new_map.keys() {
            let paillier_key = key
                .paillier_key_vec
                .get((old_party_index - 1) as usize)
                .unwrap()
                .clone();
            let h1_h2_n_tilde = key
                .h1_h2_n_tilde_vec
                .get((old_party_index - 1) as usize)
                .unwrap()
                .clone();
            paillier_key_h1_h2_n_tilde_hash_map.insert(
                *old_to_new_map.get(old_party_index).unwrap(),
                (paillier_key, h1_h2_n_tilde),
            );
        }

        for new_party_index in paillier_key_h1_h2_n_tilde_hash_map.keys() {
            if *new_party_index <= current_len {
                key.paillier_key_vec[(new_party_index - 1) as usize] =
                    paillier_key_h1_h2_n_tilde_hash_map
                        .get(new_party_index)
                        .unwrap()
                        .clone()
                        .0;
                key.h1_h2_n_tilde_vec[(new_party_index - 1) as usize] =
                    paillier_key_h1_h2_n_tilde_hash_map
                        .get(new_party_index)
                        .unwrap()
                        .clone()
                        .1;
            } else {
                key.paillier_key_vec.insert(
                    (new_party_index - 1) as usize,
                    paillier_key_h1_h2_n_tilde_hash_map
                        .get(new_party_index)
                        .unwrap()
                        .clone()
                        .0,
                );
                key.h1_h2_n_tilde_vec.insert(
                    (new_party_index - 1) as usize,
                    paillier_key_h1_h2_n_tilde_hash_map
                        .get(new_party_index)
                        .unwrap()
                        .clone()
                        .1,
                );
            }
        }

        for join_message in new_parties.iter() {
            let party_index = join_message.get_party_index()?;
            if party_index <= current_len {
                key.paillier_key_vec[(party_index - 1) as usize] =
                    join_message.ek.clone();
                key.h1_h2_n_tilde_vec[(party_index - 1) as usize] =
                    join_message.dlog_statement.clone();
            } else {
                key.paillier_key_vec.insert(
                    (party_index - 1) as usize,
                    join_message.ek.clone(),
                );
                key.h1_h2_n_tilde_vec.insert(
                    (party_index - 1) as usize,
                    join_message.dlog_statement.clone(),
                );
            }
        }
        let old_party_index = key.i;
        key.i = *old_to_new_map.get(&key.i).unwrap();
        key.t = new_t;
        key.n = new_n;

        RefreshMessage::distribute(old_party_index, key, new_t, new_n)
    }

    pub fn collect(
        refresh_messages: &[Self],
        local_key: &mut LocalKey<E>,
        new_dk: DecryptionKey,
        join_messages: &[JoinMessage<E, H>],
        current_t: u16,
    ) -> FsDkrResult<()> {
        let new_n = refresh_messages.len() + join_messages.len();
        RefreshMessage::validate_collect(
            refresh_messages,
            current_t,
            new_n as u16,
        )?;

        for refresh_message in refresh_messages.iter() {
            for i in 0..new_n {
                let statement = PDLwSlackStatement {
                    ciphertext: refresh_message.points_encrypted_vec[i].clone(),
                    ek: local_key.paillier_key_vec[i].clone(),
                    Q: refresh_message.points_committed_vec[i].clone(),
                    G: Point::<E>::generator().to_point(),
                    h1: local_key.h1_h2_n_tilde_vec[i].base.clone(),
                    h2: local_key.h1_h2_n_tilde_vec[i].value.clone(),
                    N_tilde: local_key.h1_h2_n_tilde_vec[i].modulus.clone(),
                };
                refresh_message.pdl_proof_vec[i].verify(&statement)?;
                if !refresh_message.range_proofs[i].verify(
                    &statement.ciphertext,
                    &statement.ek,
                    &local_key.h1_h2_n_tilde_vec[i],
                ) {
                    return Err(FsDkrError::RangeProof { party_index: i });
                }
            }
        }

        // Verify ring-pedersen parameters
        for refresh_message in refresh_messages.iter() {
            refresh_message
                .ring_pedersen_pi_prm_proof
                .verify(&refresh_message.ring_pedersen_pi_prm_statement)
                .map_err(|_| FsDkrError::RingPedersenProofValidation {
                    party_index: refresh_message.party_index,
                })?;
        }

        for join_message in join_messages.iter() {
            join_message
                .ring_pedersen_pi_prm_proof
                .verify(&join_message.ring_pedersen_pi_prm_statement)
                .map_err(|_| FsDkrError::RingPedersenProofValidation {
                    party_index: join_message.party_index.unwrap_or(0),
                })?;
        }

        let old_ek =
            local_key.paillier_key_vec[(local_key.i - 1) as usize].clone();
        let (cipher_text_sum, li_vec) = RefreshMessage::get_ciphertext_sum(
            refresh_messages,
            local_key.i,
            &local_key.vss_scheme.parameters,
            &old_ek,
        );

        for refresh_message in refresh_messages.iter() {
            if refresh_message
                .dk_correctness_proof
                .verify(&refresh_message.ek, SALT_STRING)
                .is_err()
            {
                return Err(FsDkrError::PaillierVerificationError {
                    party_index: refresh_message.party_index,
                });
            }
            let n_length = refresh_message.ek.n.bit_length();
            if !(crate::PAILLIER_KEY_SIZE - 1..=crate::PAILLIER_KEY_SIZE)
                .contains(&n_length)
            {
                return Err(FsDkrError::ModuliTooSmall {
                    party_index: refresh_message.party_index,
                    moduli_size: n_length,
                });
            }

            // if the proof checks, we add the new paillier public key to the
            // key
            local_key.paillier_key_vec
                [(refresh_message.party_index - 1) as usize] =
                refresh_message.ek.clone();
        }

        for join_message in join_messages {
            let party_index = join_message.get_party_index()?;

            if join_message
                .dk_correctness_proof
                .verify(&join_message.ek, SALT_STRING)
                .is_err()
            {
                return Err(FsDkrError::PaillierVerificationError {
                    party_index,
                });
            }

            // creating an inverse dlog statement
            let dlog_statement_base_h2 = PiPrmStatement {
                modulus: join_message.dlog_statement.modulus.clone(),
                // Base and value are swapped because we're using h1's statement.
                base: join_message.dlog_statement.value.clone(),
                value: join_message.dlog_statement.base.clone(),
            };
            if join_message
                .composite_dlog_proof_base_h1
                .verify(&join_message.dlog_statement)
                .is_err()
                || join_message
                    .composite_dlog_proof_base_h2
                    .verify(&dlog_statement_base_h2)
                    .is_err()
            {
                return Err(FsDkrError::DLogProofValidation { party_index });
            }

            let n_length = join_message.ek.n.bit_length();
            if !(crate::PAILLIER_KEY_SIZE - 1..=crate::PAILLIER_KEY_SIZE)
                .contains(&n_length)
            {
                //if n_length > crate::PAILLIER_KEY_SIZE || n_length <
                // crate::PAILLIER_KEY_SIZE - 1 {
                return Err(FsDkrError::ModuliTooSmall {
                    party_index: join_message.get_party_index()?,
                    moduli_size: n_length,
                });
            }

            // if the proof checks, we add the new paillier public key to the
            // key
            local_key.paillier_key_vec[(party_index - 1) as usize] =
                join_message.ek.clone();
        }

        let new_share =
            Paillier::decrypt(&local_key.paillier_dk, cipher_text_sum)
                .0
                .into_owned();

        let new_share_fe: Scalar<E> = Scalar::<E>::from(&new_share);

        // zeroize the old dk key
        local_key.paillier_dk.q.zeroize();
        local_key.paillier_dk.p.zeroize();
        local_key.paillier_dk = new_dk;

        // update old key and output new key
        local_key.keys_linear.x_i = new_share_fe.clone();
        local_key.keys_linear.y = Point::<E>::generator() * new_share_fe;

        // update local key list of local public keys (X_i = g^x_i is updated by
        // adding all committed points to that party)
        for i in 0..refresh_messages.len() + join_messages.len() {
            local_key.pk_vec.insert(
                i,
                refresh_messages[0].points_committed_vec[i].clone()
                    * li_vec[0].clone(),
            );
            for j in 1..refresh_messages.len() {
                local_key.pk_vec[i] = local_key.pk_vec[i].clone()
                    + refresh_messages[j].points_committed_vec[i].clone()
                        * li_vec[j].clone();
            }
        }

        Ok(())
    }
}
