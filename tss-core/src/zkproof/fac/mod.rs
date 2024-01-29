#![allow(non_snake_case)]

use crate::{
    security_level::{L, L_PLUS_EPSILON, SEC_BYTES},
    utilities::{
        mod_pow_with_negative, RingPedersenParams, RingPedersenWitness,
    },
};

use curv::{
    arithmetic::{traits::*, Modulo},
    BigInt,
};

use merlin::Transcript;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PiFacError {
    Statement,
    Serialization,
    Proof,
}

impl From<Box<bincode::ErrorKind>> for PiFacError {
    fn from(_: Box<bincode::ErrorKind>) -> Self {
        Self::Serialization
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiFacStatement {
    pub RPParam: RingPedersenParams,
    pub N0: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiFacWitness {
    pub RPWitness: RingPedersenWitness,
    pub p: BigInt,
    pub q: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiFacCommitment {
    pub P: BigInt,
    pub Q: BigInt,
    pub A: BigInt,
    pub B: BigInt,
    pub T: BigInt,
    pub sigma: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiFacProof {
    pub cmt: PiFacCommitment,
    pub z1: BigInt,
    pub z2: BigInt,
    pub w1: BigInt,
    pub w2: BigInt,
    pub v: BigInt,
}

impl PiFacProof {
    pub fn prove(
        statement: &PiFacStatement,
        witness: &PiFacWitness,
    ) -> Result<Self, PiFacError> {
        let mone = BigInt::from(-1);
        let two = BigInt::from(2);
        let l_exp = BigInt::pow(&two, L as u32);
        let lplus_exp = BigInt::pow(&two, L_PLUS_EPSILON as u32);

        // TODO: not sure in which domain we're taking sqrt of N0. However, we can still use bound of 1.

        // let mut sqrtN0 = match sqrt_comp(
        //     &statement.N0,
        //     &witness.RPWitness.p,
        //     &witness.RPWitness.q,
        // ) {
        //     Ok(sqrtN0) => sqrtN0,
        //     Err(_) => return Err(PiFacError::Statement),
        // };
        // if &sqrtN0 < &mone {
        //     sqrtN0 = -&sqrtN0;
        // }
        let sqrtN0 = BigInt::from(1); // bound

        // 2^{l+epsilon} sqrt(N0)
        let lplus_sqrtN0 = lplus_exp.mul(&sqrtN0);
        // 2^{l} \hat{N}
        let l_N = l_exp.mul(&statement.RPParam.N);
        // 2^{l} N0 \hat{N}
        let l_N0_N = l_exp.mul(&statement.N0).mul(&statement.RPParam.N);
        // 2^{l+epsilon} N0 \hat{N}
        let lplus_N0_N = lplus_exp.mul(&statement.N0).mul(&statement.RPParam.N);
        // 2^{l+epsilon} \hat{N}
        let lplus_N = lplus_exp.mul(&statement.RPParam.N);

        let alpha =
            BigInt::sample_range(&mone.mul(&lplus_sqrtN0), &lplus_sqrtN0);
        let beta =
            BigInt::sample_range(&mone.mul(&lplus_sqrtN0), &lplus_sqrtN0);
        let mu = BigInt::sample_range(&mone.mul(&l_N), &l_N);
        let nu = BigInt::sample_range(&mone.mul(&l_N), &l_N);
        let sigma = BigInt::sample_range(&mone.mul(&l_N0_N), &l_N0_N);
        let r = BigInt::sample_range(&mone.mul(&lplus_N0_N), &lplus_N0_N);
        let x = BigInt::sample_range(&mone.mul(&lplus_N), &lplus_N);
        let y = BigInt::sample_range(&mone.mul(&lplus_N), &lplus_N);

        let P = BigInt::mod_mul(
            &BigInt::mod_pow(
                &statement.RPParam.s,
                &witness.p,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &mu,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        let Q = BigInt::mod_mul(
            &BigInt::mod_pow(
                &statement.RPParam.s,
                &witness.q,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &nu,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        let A = BigInt::mod_mul(
            &mod_pow_with_negative(
                &statement.RPParam.s,
                &alpha,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &x,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        let B = BigInt::mod_mul(
            &mod_pow_with_negative(
                &statement.RPParam.s,
                &beta,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &y,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        let T = BigInt::mod_mul(
            &mod_pow_with_negative(&Q, &alpha, &statement.RPParam.N),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &r,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        let cmt = PiFacCommitment {
            A,
            B,
            P,
            Q,
            T,
            sigma: sigma.clone(),
        };

        let mut transcript = Transcript::new(b"PiFacProof");
        transcript.append_message(
            b"PiFacStatement",
            &bincode::serialize(&statement)?,
        );
        transcript
            .append_message(b"PiFacCommitment", &bincode::serialize(&cmt)?);
        let mut challenge_bytes = [0u8; SEC_BYTES];
        transcript.challenge_bytes(b"PiFacChallenge", &mut challenge_bytes);
        let e = BigInt::from_bytes(&challenge_bytes);
        // TODO: also sample the sign bit?

        let sigmahat = &sigma.sub(&nu.mul(&witness.p));

        let z1 = BigInt::add(&alpha, &e.mul(&witness.p));
        let z2 = BigInt::add(&beta, &e.mul(&witness.q));
        let w1 = BigInt::add(&x, &e.mul(&mu));
        let w2 = BigInt::add(&y, &e.mul(&nu));
        let v = BigInt::add(&r, &e.mul(&sigmahat));

        Ok(PiFacProof {
            cmt,
            v,
            w1,
            w2,
            z1,
            z2,
        })
    }

    pub fn verify(
        statement: &PiFacStatement,
        proof: &PiFacProof,
    ) -> Result<(), PiFacError> {
        let mut transcript = Transcript::new(b"PiFacProof");
        transcript.append_message(
            b"PiFacStatement",
            &bincode::serialize(&statement)?,
        );
        transcript.append_message(
            b"PiFacCommitment",
            &bincode::serialize(&proof.cmt)?,
        );
        let mut challenge_bytes = [0u8; SEC_BYTES];
        transcript.challenge_bytes(b"PiFacChallenge", &mut challenge_bytes);
        let e = BigInt::from_bytes(&challenge_bytes);
        // TODO: also sample the sign bit?

        let R = BigInt::mod_mul(
            &BigInt::mod_pow(
                &statement.RPParam.s,
                &statement.N0,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &proof.cmt.sigma,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        // first check
        let first_ls = BigInt::mod_mul(
            &mod_pow_with_negative(
                &statement.RPParam.s,
                &proof.z1,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &proof.w1,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        let first_rs = BigInt::mod_mul(
            &proof.cmt.A,
            &mod_pow_with_negative(&proof.cmt.P, &e, &statement.RPParam.N),
            &statement.RPParam.N,
        );
        if first_ls != first_rs {
            return Err(PiFacError::Proof);
        }
        // second check
        let second_ls = BigInt::mod_mul(
            &mod_pow_with_negative(
                &statement.RPParam.s,
                &proof.z2,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &proof.w2,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        let second_rs = BigInt::mod_mul(
            &proof.cmt.B,
            &mod_pow_with_negative(&proof.cmt.Q, &e, &statement.RPParam.N),
            &statement.RPParam.N,
        );
        if second_ls != second_rs {
            return Err(PiFacError::Proof);
        }
        // third check
        let third_ls = BigInt::mod_mul(
            &mod_pow_with_negative(
                &proof.cmt.Q,
                &proof.z1,
                &statement.RPParam.N,
            ),
            &mod_pow_with_negative(
                &statement.RPParam.t,
                &proof.v,
                &statement.RPParam.N,
            ),
            &statement.RPParam.N,
        );
        let third_rs = BigInt::mod_mul(
            &proof.cmt.T,
            &mod_pow_with_negative(&R, &e, &statement.RPParam.N),
            &statement.RPParam.N,
        );
        if third_ls != third_rs {
            return Err(PiFacError::Proof);
        }

        // range check
        // we take sqrt{N0} == 1
        if proof.z1.bit_length() > L_PLUS_EPSILON {
            return Err(PiFacError::Proof);
        }
        if proof.z2.bit_length() > L_PLUS_EPSILON {
            return Err(PiFacError::Proof);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utilities::generate_safe_h1_h2_N_tilde;

    #[test]
    fn test_prove() {
        let (rpparams, rpwitnes) = generate_safe_h1_h2_N_tilde();
        let (rpparam2, rpwitness2) = generate_safe_h1_h2_N_tilde();
        let statement = PiFacStatement {
            N0: rpparam2.N,
            RPParam: rpparams,
        };
        let witness = PiFacWitness {
            RPWitness: rpwitnes,
            p: rpwitness2.p,
            q: rpwitness2.q,
        };
        let proof = PiFacProof::prove(&statement, &witness);
        assert!(proof.is_ok());
        let res = PiFacProof::verify(&statement, &proof.unwrap());
        assert!(res.is_ok());
    }
}
