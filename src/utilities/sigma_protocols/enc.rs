/*
    zk-paillier
    Copyright 2018 by Kzen Networks
    zk-paillier is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.
    @license GPL-3.0+ <https://github.com/KZen-networks/zk-paillier/blob/master/LICENSE>
*/
use std::iter;
use std::marker::PhantomData;
use std::ops::Shl;

use bitvec::prelude::*;
use curv::cryptographic_primitives::hashing::Digest;
use curv::cryptographic_primitives::hashing::DigestExt;
use curv::elliptic::curves::Curve;
use curv::BigInt;
use curv::{arithmetic::traits::*, elliptic::curves::Point};
use paillier::{DecryptionKey, EncryptionKey, KeyGeneration, Paillier};
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::IncorrectProof;

use crate::error::FsDkrError;
use crate::error::FsDkrResult;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingPedersenStatement<E: Curve, H: Digest + Clone> {
    S: BigInt,
    T: BigInt,
    N: BigInt,
    phi: BigInt,
    phantom: PhantomData<(E, H)>,
}

pub struct RingPedersenWitness<E: Curve, H: Digest + Clone> {
    p: BigInt,
    q: BigInt,
    lambda: BigInt,
    phantom: PhantomData<(E, H)>,
}

impl<E: Curve, H: Digest + Clone> RingPedersenStatement<E, H> {
    pub fn generate() -> (Self, RingPedersenWitness<E, H>) {
        let (ek_tilde, dk_tilde) =
            Paillier::keypair_with_modulus_size(crate::PAILLIER_KEY_SIZE).keys();
        let one = BigInt::one();
        let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
        let r = BigInt::sample_below(&ek_tilde.n);
        let lambda = BigInt::sample_below(&phi);
        let t = BigInt::mod_pow(&r, &BigInt::from(2), &ek_tilde.n);
        let s = BigInt::mod_pow(&t, &lambda, &ek_tilde.n);

        (
            Self {
                S: s,
                T: t,
                N: ek_tilde.n,
                phi: phi,
                phantom: PhantomData,
            },
            RingPedersenWitness {
                p: dk_tilde.p,
                q: dk_tilde.q,
                lambda,
                phantom: PhantomData,
            },
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingPedersenProof<E: Curve, H: Digest + Clone> {
    A: Vec<BigInt>,
    Z: Vec<BigInt>,
    phantom: PhantomData<(E, H)>,
}

// Link to the UC non-interactive threshold ECDSA paper
impl<E: Curve, H: Digest + Clone> RingPedersenProof<E, H> {
    pub fn prove(
        witness: &RingPedersenWitness<E, H>,
        statement: &RingPedersenStatement<E, H>,
    ) -> RingPedersenProof<E, H> {
        // 1. Sample alphas from 1 -> m from \phi(N)
        let mut a = [(); crate::M_SECURITY].map(|_| BigInt::zero());
        let mut A = [(); crate::M_SECURITY].map(|_| BigInt::zero());
        let mut hash = H::new();
        for i in 0..crate::M_SECURITY {
            // TODO: Consider ensuring we get a unit element of this subgroup
            let a_i = BigInt::sample_below(&statement.phi);
            a[i] = a_i.clone();
            let A_i = BigInt::mod_pow(&statement.T, &a_i, &statement.N);
            A[i] = A_i.clone();
            hash = H::chain_bigint(hash, &A_i);
        }

        let e: BigInt = hash.result_bigint();
        let bitwise_e: BitVec<u8, Lsb0> = BitVec::from_vec(e.to_bytes());

        let mut Z = [(); crate::M_SECURITY].map(|_| BigInt::zero());
        for i in 0..crate::M_SECURITY {
            let e_i = if bitwise_e[i] {
                BigInt::one()
            } else {
                BigInt::zero()
            };
            let z_i = BigInt::mod_add(&a[i], &(e_i * &witness.lambda), &statement.phi);
            Z[i] = z_i;
        }

        Self {
            A: A.to_vec(),
            Z: Z.to_vec(),
            phantom: PhantomData,
        }
    }

    pub fn verify(
        proof: &RingPedersenProof<E, H>,
        statement: &RingPedersenStatement<E, H>,
    ) -> FsDkrResult<()> {
        let mut hash = H::new();
        for i in 0..crate::M_SECURITY {
            hash = H::chain_bigint(hash, &proof.A[i]);
        }

        let e: BigInt = hash.result_bigint();
        let bitwise_e: BitVec<u8, Lsb0> = BitVec::from_vec(e.to_bytes());

        for i in 0..crate::M_SECURITY {
            let mut e_i = 0;
            if bitwise_e[i] {
                e_i = 1;
            }

            if BigInt::mod_pow(&statement.T, &proof.Z[i], &statement.N)
                == BigInt::mod_mul(
                    &proof.A[i],
                    &BigInt::mod_pow(&statement.S, &BigInt::from(e_i), &statement.N),
                    &statement.N,
                )
            {
                continue;
            } else {
                return Err(FsDkrError::RingPedersenProofError);
            }
        }
        Ok(())
    }
}


