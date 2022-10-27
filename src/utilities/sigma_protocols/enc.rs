use std::iter;
use std::marker::PhantomData;
use std::ops::Shl;
use curv::cryptographic_primitives::hashing::Digest;
use curv::cryptographic_primitives::hashing::DigestExt;
use curv::elliptic::curves::Curve;
use curv::BigInt;
use curv::{arithmetic::traits::*, elliptic::curves::Point};
use paillier::{DecryptionKey, EncryptionKey, KeyGeneration, Paillier};
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::IncorrectProof;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncSetupParameters<E: Curve, H: Digest + Clone> {
    S: BigInt,
    T: BigInt,
    N: BigInt,
    phantom: PhantomData<(E, H)>,
}

pub struct EncCommonInput<E: Curve, H: Digest + Clone> {
    N_0: BigInt,
    K: BigInt,
    phantom: PhantomData<(E, H)>,
}

pub struct EncSecretInput<E: Curve, H: Digest + Clone> {
    k: BigInt,
    rho: BigInt,
    phantom: PhantomData<(E, H)>,
}

pub struct EncWitness<E: Curve, H: Digest + Clone> {
    phantom: PhantomData<(E, H)>,
}

pub struct EncProof<E: Curve, H: Digest + Clone> {
    phantom: PhantomData<(E, H)>,
}
