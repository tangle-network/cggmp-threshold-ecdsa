pub mod keygen;
pub mod sign;
pub mod party_i;
pub mod traits;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
    Phase5BadSum,
    Phase6Error,
}


#[derive(Clone, Debug)]
pub struct ErrorType {
    pub error_type: String,
    pub bad_actors: Vec<usize>,
    pub data: Vec<u8>,
}
