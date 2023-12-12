#![allow(non_snake_case)]

use curv::arithmetic::traits::*;
use curv::BigInt;
use paillier::{DecryptionKey, EncryptionKey, KeyGeneration, Paillier};
use serde::{Deserialize, Serialize};

use crate::security_level::DEFAULT_LEVEL;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingPedersenParams {
    // modulus N = p*q, where p,q are either safe primes or normal primes
    pub N: BigInt,
    // s and t such that t is in the subgroup generateb s.
    pub s: BigInt,
    pub t: BigInt,
}

// RingPedersenWitness provides witness values for proving correctness of RingPedersenParams
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingPedersenWitness {
    pub lambda: BigInt,
    pub lambdaInv: BigInt,
    pub phi: BigInt,
}

pub fn generate_safe_h1_h2_N_tilde() -> (RingPedersenParams, RingPedersenWitness)
{
    let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes_with_modulus_size(
        DEFAULT_LEVEL.paillier_key_size,
    )
    .keys();
    get_related_values(&ek_tilde, &dk_tilde)
}

// generate_normal_h1_h2_N_tilde generates Paillier modulus N = p*q and related
// values h1 and h2 such that h2 = h1^lambda and h1=h2^lambda_inv.
pub fn generate_normal_h1_h2_N_tilde(
) -> (RingPedersenParams, RingPedersenWitness) {
    let (ek_tilde, dk_tilde) =
        Paillier::keypair_with_modulus_size(DEFAULT_LEVEL.paillier_key_size)
            .keys();
    get_related_values(&ek_tilde, &dk_tilde)
}

fn get_related_values(
    ek: &EncryptionKey,
    dk: &DecryptionKey,
) -> (RingPedersenParams, RingPedersenWitness) {
    // Generate h1 and h2 (s and t in CGGMP20) following section 6.4.1 (and Figure 6) of CGGMP20 .
    // Ref: <https://eprint.iacr.org/2021/060.pdf#page=38>.
    let one = BigInt::one();
    let phi = (&dk.p - &one) * (&dk.q - &one);
    let tau = BigInt::sample_below(&ek.n);
    let h1 = BigInt::mod_pow(&tau, &BigInt::from(2), &ek.n);
    // For GG18/20 implementation, we need the inverse of lambda as well.
    let (lambda, lambdaInv) = loop {
        let lambda_ = BigInt::sample_below(&phi);
        match BigInt::mod_inv(&lambda_, &phi) {
            Some(inv) => break (lambda_, inv),
            None => continue,
        }
    };
    let h2 = BigInt::mod_pow(&h1, &lambda, &ek.n);
    (
        RingPedersenParams {
            N: ek.n.clone(),
            s: h1,
            t: h2,
        },
        RingPedersenWitness {
            lambda,
            lambdaInv,
            phi,
        },
    )
}

pub fn sample_relatively_prime_integer(n: &BigInt) -> BigInt {
    let mut sample = BigInt::sample_below(n);
    while BigInt::gcd(&sample, n) != BigInt::from(1) {
        sample = BigInt::sample_below(n);
    }
    sample
}

pub fn mod_pow_with_negative(
    v: &BigInt,
    pow: &BigInt,
    modulus: &BigInt,
) -> BigInt {
    if BigInt::is_negative(pow) {
        let temp = BigInt::mod_pow(v, &pow.abs(), modulus);
        BigInt::mod_inv(&temp, modulus).unwrap_or_else(BigInt::zero)
    } else {
        BigInt::mod_pow(v, pow, modulus)
    }
}

/// Extend or truncate a vector of bytes to a fixed length array.
///
/// If the length is less than the target amount `N` leading zeroes
/// are prepended, if the length exceeds `N` it is truncated.
///
/// The `ChaChaRng::from_seed()` function requires a `[u8; 32]` but the
/// chaining of the BigInt's does not guarantee the length
/// of the underlying bytes so we use this to ensure we seed the RNG
/// using the correct number of bytes.
pub fn fixed_array<const N: usize>(
    mut seed: Vec<u8>,
) -> Result<[u8; 32], Vec<u8>> {
    use std::cmp::Ordering;
    match seed.len().cmp(&N) {
        Ordering::Greater => {
            seed.truncate(N);
        }
        Ordering::Less => {
            let padding = vec![0; N - seed.len()];
            seed.splice(..0, padding.iter().cloned());
        }
        _ => {}
    }
    seed.try_into()
}
