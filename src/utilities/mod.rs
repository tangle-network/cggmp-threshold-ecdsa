use curv::{
	arithmetic::{Integer, Samplable},
	BigInt,
};

pub mod aff_g;
pub mod mta;
pub mod zk_pdl;
pub mod zk_pdl_with_slack;

pub fn sample_relatively_prime_integer(N: BigInt) -> BigInt {
	let mut sample = BigInt::sample_below(&N);
	while BigInt::gcd(&sample, &N) != BigInt::from(1) {
		sample = BigInt::sample_below(&N);
	}
	sample
}

const SecParam: usize = 256;
const SecBytes: usize = SecParam / 8;
const OTParam: usize = 128;
const OTBytes: usize = OTParam / 8;
const StatParam: usize = fs_dkr::M_SECURITY;

// ZKModIterations is the number of iterations that are performed to prove the validity of
// a Paillier-Blum modulus N.
// Theoretically, the number of iterations corresponds to the statistical security parameter,
// and would be 80.
// The way it is used in the refresh protocol ensures that the prover cannot guess in advance the
// secret ρ used to instantiate the hash function.
// Since sampling primes is expensive, we argue that the security can be reduced.
const ZKModIterations: usize = 12;

const L: usize = 1 * SecParam; // = 256
const LPrime: usize = 5 * SecParam; // = 1280
const Epsilon: usize = 2 * SecParam; // = 512
const LPlusEpsilon: usize = L + Epsilon; // = 768
const LPrimePlusEpsilon: usize = LPrime + Epsilon; // = 1792

const BitsIntModN: usize = 8 * SecParam; // = 2048
const BytesIntModN: usize = BitsIntModN / 8; // = 256

const BitsBlumPrime: usize = 4 * SecParam; // = 1024
const BitsPaillier: usize = 2 * BitsBlumPrime; // = 2048

const BytesPaillier: usize = BitsPaillier / 8; // = 256
const BytesCiphertext: usize = 2 * BytesPaillier; // = 512
