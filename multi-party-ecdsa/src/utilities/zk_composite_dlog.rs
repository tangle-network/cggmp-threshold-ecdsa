//! Zero-knowledge proof that given a tuple (N~, h1, h2) as defined in GG18/GG20,
//! where N~ is a Paillier modulus and h1, h2 ∈ Z^* _N~,
//! the prover knows a secret x ∈ φ(N~) such that h1 = h2 ^ χ mod N~
//! (i.e. the prover knows log_h2 (h1) ).
//!
//! NOTE: For CGGMP20, the tuple is (N, s, t), the secret is λ
//! and this proof is referred to as Π^prm.
//!
//! The implementation follows section 6.4 (Figure 17) of CGGMP20:
//! <https://eprint.iacr.org/2021/060.pdf>
//!
//! But applies a Fiat-Shamir transformation to make the proof non-interactive.
//! <https://link.springer.com/content/pdf/10.1007/3-540-47721-7_12.pdf>.
//!
//! The Fiat-Shamir transformation is implemented using [merlin](https://merlin.cool/)
//! to generate the challenge bits.

use curv::arithmetic::traits::*;
use curv::BigInt;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde_with::serde_as;
use zeroize::ZeroizeOnDrop;

/// Statistical security parameter (i.e. m=80 in CGGMP20).
const STAT_SECURITY: usize = 80;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeDLogStatement {
    pub modulus: BigInt,
    pub base: BigInt,
    pub value: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct CompositeDLogWitness {
    pub exponent: BigInt,
    pub totient: BigInt,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeDLogProof {
    pub commitments: Vec<BigInt>,
    #[serde_as(as = "[_; STAT_SECURITY]")]
    pub challenges: [ChallengeBit; STAT_SECURITY],
    pub responses: Vec<BigInt>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr,
)]
#[repr(u8)]
pub enum ChallengeBit {
    ZERO = 0,
    ONE = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositeDLogError {
    Serialization,
    Validation,
    Challenge,
    Proof,
}

impl From<Box<bincode::ErrorKind>> for CompositeDLogError {
    fn from(_: Box<bincode::ErrorKind>) -> Self {
        Self::Serialization
    }
}

/// Computes Fiat-Shamir transform challenges using merlin transcript.
fn compute_challenges(
    statement: &CompositeDLogStatement,
    commitments: &[BigInt],
) -> Result<[ChallengeBit; STAT_SECURITY], CompositeDLogError> {
    let mut transcript = Transcript::new(b"CompositeDLogProof");
    transcript.append_message(
        b"CompositeDLogStatement",
        &bincode::serialize(&statement)?,
    );
    transcript.append_message(
        b"CompositeDLogCommitments",
        &bincode::serialize(&commitments)?,
    );

    // Each challenge is only a bit so we divide 8.
    let mut challenge_bytes = [0u8; STAT_SECURITY / 8];
    transcript
        .challenge_bytes(b"CompositeDLogChallenges", &mut challenge_bytes);

    // Parses challenge bits.
    let mut challenge_bits = [ChallengeBit::ZERO; STAT_SECURITY];
    for (idx, byte) in challenge_bytes.iter().enumerate() {
        // We're only looking for non-zero bits (i.e. 1)
        // since the rest are already set to zero by default.
        let start = byte.leading_zeros(); // inclusive.
        if start < 8 {
            // Skips case of all zeros.
            let end = 8 - byte.trailing_zeros(); // exclusive.
            for i in start..end {
                if (byte >> (7 - i)) & 1 == 1 {
                    challenge_bits[(idx * 8) + i as usize] = ChallengeBit::ONE
                }
            }
        }
    }

    Ok(challenge_bits)
}

impl CompositeDLogProof {
    pub fn prove(
        statement: &CompositeDLogStatement,
        witness: &CompositeDLogWitness,
    ) -> Result<Self, CompositeDLogError> {
        // a_i ← Z_{φ(N)} in CGGMP20.
        let mut randomness: Vec<BigInt> = Vec::with_capacity(STAT_SECURITY);
        // A_i = t^{a_i} mod N in CGGMP20.
        let mut commitments: Vec<BigInt> = Vec::with_capacity(STAT_SECURITY);

        for _ in 0..STAT_SECURITY {
            let random = BigInt::sample_below(&witness.totient);
            commitments.push(BigInt::mod_pow(
                &statement.base,
                &random,
                &statement.modulus,
            ));
            randomness.push(random);
        }

        // e_i ← {0, 1} in CGGMP20.
        let challenges = compute_challenges(statement, &commitments)?;

        // z_i = a_i + e_i * λ mod φ(N) in CGGMP20.
        let responses = challenges
            .iter()
            .zip(randomness)
            .map(|(challenge, random)| match challenge {
                ChallengeBit::ZERO => random,
                ChallengeBit::ONE => BigInt::mod_add(
                    &random,
                    &witness.exponent,
                    &witness.totient,
                ),
            })
            .collect();

        Ok(CompositeDLogProof {
            commitments,
            challenges,
            responses,
        })
    }

    pub fn verify(
        &self,
        statement: &CompositeDLogStatement,
    ) -> Result<(), CompositeDLogError> {
        // Validate expected lengths i.e m in CGGMP20.
        if self.commitments.len() != STAT_SECURITY
            || self.challenges.len() != STAT_SECURITY
            || self.responses.len() != STAT_SECURITY
        {
            return Err(CompositeDLogError::Validation);
        }

        // Verify Fiat-Shamir challenges .i.e e_i ← {0, 1} in CGGMP20.
        let challenges = compute_challenges(statement, &self.commitments)?;
        if challenges != self.challenges {
            return Err(CompositeDLogError::Challenge);
        }

        // Verify responses i.e t^{z_i} = {A_i} * s^{e_i} mod N in CGGMP20.
        for ((commitment, challenge), response) in self
            .commitments
            .iter()
            .zip(&self.challenges)
            .zip(&self.responses)
        {
            if BigInt::mod_pow(&statement.base, response, &statement.modulus)
                != match challenge {
                    ChallengeBit::ZERO => commitment.clone(),
                    ChallengeBit::ONE => BigInt::mod_mul(
                        commitment,
                        &statement.value,
                        &statement.modulus,
                    ),
                }
            {
                return Err(CompositeDLogError::Proof);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;
    use crate::gg_2020::party_i::generate_h1_h2_N_tilde;

    #[test]
    fn valid_composite_dlog_proof_works() {
        let (N_tilde, h1, h2, xhi, xhi_inv, phi) = generate_h1_h2_N_tilde();
        let statement_base_h1 = CompositeDLogStatement {
            modulus: N_tilde.clone(),
            base: h1.clone(),
            value: h2.clone(),
        };
        let witness_base_h1 = CompositeDLogWitness {
            exponent: xhi,
            totient: phi.clone(),
        };
        let proof_base_h1 =
            CompositeDLogProof::prove(&statement_base_h1, &witness_base_h1)
                .unwrap();
        let result_base_h1 = proof_base_h1.verify(&statement_base_h1);
        assert!(result_base_h1.is_ok());

        let statement_base_h2 = CompositeDLogStatement {
            modulus: N_tilde,
            base: h2,
            value: h1,
        };
        let witness_base_h2 = CompositeDLogWitness {
            exponent: xhi_inv,
            totient: phi,
        };
        let proof_base_h2 =
            CompositeDLogProof::prove(&statement_base_h2, &witness_base_h2)
                .unwrap();
        let result_base_h2 = proof_base_h2.verify(&statement_base_h2);
        assert!(result_base_h2.is_ok());
    }

    #[test]
    fn invalid_composite_dlog_proof_fails() {
        let (N_tilde, h1, h2, _, _, phi) = generate_h1_h2_N_tilde();
        // We use a fake/wrong/guessed exponent.
        let xhi = BigInt::sample_below(&phi);
        let statement = CompositeDLogStatement {
            modulus: N_tilde.clone(),
            base: h1.clone(),
            value: h2.clone(),
        };
        let witness = CompositeDLogWitness {
            exponent: xhi,
            totient: phi.clone(),
        };
        let proof = CompositeDLogProof::prove(&statement, &witness).unwrap();
        let result = proof.verify(&statement);
        assert_eq!(result, Err(CompositeDLogError::Proof));
    }
}
