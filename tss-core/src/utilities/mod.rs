#![allow(non_snake_case)]

use curv::arithmetic::traits::*;
use curv::BigInt;
use paillier::{DecryptionKey, EncryptionKey, KeyGeneration, Paillier};

use crate::security_level::DEFAULT_LEVEL;

pub fn generate_safe_h1_h2_N_tilde(
) -> (BigInt, BigInt, BigInt, BigInt, BigInt, BigInt) {
    let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes_with_modulus_size(
        DEFAULT_LEVEL.paillier_key_size,
    )
    .keys();
    let (h1, h2, lambda, lambda_inv, phi) =
        get_related_values(&ek_tilde, &dk_tilde);

    (ek_tilde.n, h1, h2, lambda, lambda_inv, phi)
}

// generate_normal_h1_h2_N_tilde generates Paillier modulus N = p*q and related
// values h1 and h2 such that h2 = h1^lambda and h1=h2^lambda_inv.
pub fn generate_normal_h1_h2_N_tilde(
) -> (BigInt, BigInt, BigInt, BigInt, BigInt, BigInt) {
    let (ek_tilde, dk_tilde) =
        Paillier::keypair_with_modulus_size(DEFAULT_LEVEL.paillier_key_size)
            .keys();
    let (h1, h2, lambda, lambda_inv, phi) =
        get_related_values(&ek_tilde, &dk_tilde);
    return (ek_tilde.n, h1, h2, lambda, lambda_inv, phi);
}

fn get_related_values(
    ek: &EncryptionKey,
    dk: &DecryptionKey,
) -> (BigInt, BigInt, BigInt, BigInt, BigInt) {
    // Generate h1 and h2 (s and t in CGGMP20) following section 6.4.1 (and Figure 6) of CGGMP20 .
    // Ref: <https://eprint.iacr.org/2021/060.pdf#page=38>.
    let one = BigInt::one();
    let phi = (&dk.p - &one) * (&dk.q - &one);
    let tau = BigInt::sample_below(&ek.n);
    let h1 = BigInt::mod_pow(&tau, &BigInt::from(2), &ek.n);
    // For GG18/20 implementation, we need the inverse of lambda as well.
    let (lambda, lambda_inv) = loop {
        let lambda_ = BigInt::sample_below(&phi);
        match BigInt::mod_inv(&lambda_, &phi) {
            Some(inv) => break (lambda_, inv),
            None => continue,
        }
    };
    let h2 = BigInt::mod_pow(&h1, &lambda, &ek.n);
    return (h1, h2, lambda, lambda_inv, phi);
}
