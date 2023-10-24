use curv::arithmetic::traits::*;
use curv::BigInt;
use paillier::{KeyGeneration, Paillier};

pub fn generate_h1_h2_N_tilde(
) -> (BigInt, BigInt, BigInt, BigInt, BigInt, BigInt) {
    // Uses safe primes in production.
    #[cfg(all(not(test), not(feature = "dev")))]
    let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();
    // Doesn't use safe primes in tests (for speed).
    #[cfg(any(test, feature = "dev"))]
    let (ek_tilde, dk_tilde) = Paillier::keypair().keys();

    // Generate h1 and h2 (s and t in CGGMP20) following section 6.4.1 (and Figure 6) of CGGMP20 .
    // Ref: <https://eprint.iacr.org/2021/060.pdf#page=38>.
    let one = BigInt::one();
    let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
    let tau = BigInt::sample_below(&ek_tilde.n);
    let h1 = BigInt::mod_pow(&tau, &BigInt::from(2), &ek_tilde.n);
    // For GG18/20 implementation, we need the inverse of lambda as well.
    let (lambda, lambda_inv) = loop {
        let lambda_ = BigInt::sample_below(&phi);
        match BigInt::mod_inv(&lambda_, &phi) {
            Some(inv) => break (lambda_, inv),
            None => continue,
        }
    };
    let h2 = BigInt::mod_pow(&h1, &lambda, &ek_tilde.n);

    (ek_tilde.n, h1, h2, lambda, lambda_inv, phi)
}
