#![allow(non_snake_case)]

use crate::{
    security_level::{SEC_BYTES, STAT_PARAM},
    utilities::{legendre, sqrt_comp},
};
use curv::{
    arithmetic::{traits::*, Modulo},
    BigInt,
};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PiModError {
    Statement,
    Serialization,
    Proof,
}

impl From<Box<bincode::ErrorKind>> for PiModError {
    fn from(_: Box<bincode::ErrorKind>) -> Self {
        Self::Serialization
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiModStatement {
    pub N: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiModWitness {
    pub p: BigInt,
    pub q: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiModCommitment {
    pub w: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PiModProof {
    pub cmt: PiModCommitment,
    pub x: Vec<BigInt>,
    pub a: Vec<bool>,
    pub b: Vec<bool>,
    pub z: Vec<BigInt>,
}

impl PiModProof {
    pub fn prove(
        statement: &PiModStatement,
        witness: &PiModWitness,
    ) -> Result<Self, PiModError> {
        let one = BigInt::from(1);
        let three = BigInt::from(3);
        let four = BigInt::from(4);
        if &witness.p % &four != three {
            return Err(PiModError::Statement);
        }
        if &witness.q % &four != three {
            return Err(PiModError::Statement);
        }
        let phi = (&witness.p - &one) * (&witness.q - &one);
        let ninv = match BigInt::mod_inv(&statement.N, &phi) {
            Some(ninv) => ninv,
            None => return Err(PiModError::Statement),
        };

        let mone = BigInt::from(-1);
        let mut w = BigInt::sample_below(&statement.N);
        while legendre(&w, &witness.p) * legendre(&w, &witness.q) != mone {
            w = BigInt::sample_below(&statement.N);
        }
        let mut y: Vec<BigInt> = Vec::with_capacity(STAT_PARAM);
        let commitment = PiModCommitment { w: w.clone() };
        let mut transcript = Transcript::new(b"PiModProof");
        transcript.append_message(
            b"PiModStatement",
            &bincode::serialize(&statement)?,
        );
        transcript.append_message(
            b"PiModCommitment",
            &bincode::serialize(&commitment)?,
        );
        let mut a: Vec<bool> = Vec::with_capacity(STAT_PARAM);
        let mut b: Vec<bool> = Vec::with_capacity(STAT_PARAM);
        let mut x: Vec<BigInt> = Vec::with_capacity(STAT_PARAM);
        let mut z: Vec<BigInt> = Vec::with_capacity(STAT_PARAM);
        'outer: for i in 0..STAT_PARAM {
            transcript.append_message(b"PiModChallengeRound", &i.to_le_bytes());
            let mut challenge_bytes = [0u8; SEC_BYTES];
            transcript.challenge_bytes(b"PiModChallenge", &mut challenge_bytes);
            let mut yi = BigInt::from_bytes(&challenge_bytes);
            yi = yi % &statement.N;
            y.push(yi.clone());
            let zi = BigInt::mod_pow(&yi, &ninv, &statement.N);
            z.push(zi.clone());

            for (ai, bi) in
                [(false, false), (false, true), (true, false), (true, true)]
            {
                let mut ypi = yi.clone();
                if ai {
                    ypi = &statement.N - ypi;
                }
                if bi {
                    ypi = BigInt::mod_mul(&w, &ypi, &statement.N);
                }
                let ypi_sqrt = sqrt_comp(&ypi, &witness.p, &witness.q);
                if ypi_sqrt.is_err() {
                    continue;
                }
                let ypi_fourth_sqrt =
                    sqrt_comp(&(ypi_sqrt.unwrap()), &witness.p, &witness.q);
                if ypi_fourth_sqrt.is_err() {
                    continue;
                }
                a.push(ai);
                b.push(bi);
                x.push(ypi_fourth_sqrt.unwrap());
                continue 'outer;
            }
            return Err(PiModError::Statement);
        }

        Ok(PiModProof {
            cmt: commitment,
            x,
            a,
            b,
            z,
        })
    }

    pub fn verify(
        statement: &PiModStatement,
        proof: &PiModProof,
    ) -> Result<(), PiModError> {
        let one = BigInt::from(1);
        let two = BigInt::from(2);
        let four = BigInt::from(4);
        if &statement.N % two != one {
            return Err(PiModError::Statement);
        }
        if BigInt::is_probable_prime(
            &statement.N,
            (STAT_PARAM / 2).try_into().unwrap(),
        ) {
            return Err(PiModError::Statement);
        }

        let mut transcript = Transcript::new(b"PiModProof");
        transcript.append_message(
            b"PiModStatement",
            &bincode::serialize(&statement)?,
        );
        transcript.append_message(
            b"PiModCommitment",
            &bincode::serialize(&proof.cmt)?,
        );
        for i in 0..STAT_PARAM {
            transcript.append_message(b"PiModChallengeRound", &i.to_le_bytes());
            let mut challenge_bytes = [0u8; SEC_BYTES];
            transcript.challenge_bytes(b"PiModChallenge", &mut challenge_bytes);
            let mut yi = BigInt::from_bytes(&challenge_bytes);
            yi = yi % &statement.N;

            let zi = match proof.z.get(i) {
                Some(zi) => zi,
                None => return Err(PiModError::Proof),
            };
            let zin = BigInt::mod_pow(zi, &statement.N, &statement.N);
            if zin != yi {
                return Err(PiModError::Proof);
            }
            let ai = match proof.a.get(i) {
                Some(ai) => *ai,
                None => return Err(PiModError::Proof),
            };
            let bi = match proof.b.get(i) {
                Some(bi) => *bi,
                None => return Err(PiModError::Proof),
            };
            if ai {
                yi = &statement.N - yi;
            }
            if bi {
                yi = BigInt::mod_mul(&proof.cmt.w, &yi, &statement.N);
            }
            let xi = match proof.x.get(i) {
                Some(xi) => xi,
                None => return Err(PiModError::Proof),
            };
            let xifourth = BigInt::mod_pow(xi, &four, &statement.N);
            if xifourth != yi {
                return Err(PiModError::Proof);
            }
        }

        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utilities::generate_safe_h1_h2_N_tilde;

    #[test]
    fn test_prove() {
        let (rpparams, rpwitness) = generate_safe_h1_h2_N_tilde();
        let statement = PiModStatement { N: rpparams.N };
        let witness = PiModWitness {
            p: rpwitness.p,
            q: rpwitness.q,
        };
        let proof = PiModProof::prove(&statement, &witness);
        assert!(proof.is_ok());
        assert!(PiModProof::verify(&statement, &proof.unwrap()).is_ok());
    }
}
