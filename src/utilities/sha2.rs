//! Wrapper for the SHA2 Sha256 algorithm that implements 
//! the serde Serialize and Deserialize traits.
use serde::{Serialize, Deserialize};
use digest::{Digest, Output};
use generic_array::typenum::U32;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Sha256 {
    #[serde(skip)]
    inner: sha2::Sha256,
}

impl Digest for Sha256 {
    type OutputSize = U32;

    fn new() -> Self {
        Self { inner: sha2::Sha256::new() }
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.inner.update(data);
    }

    fn chain(self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized {
        Self { inner: self.inner.chain(data) } 
    }

    fn finalize(self) -> Output<Self> {
        self.inner.finalize()
    }

    fn finalize_reset(&mut self) -> Output<Self> {
        self.inner.finalize_reset()
    }

    fn reset(&mut self) {
        self.inner.reset();
    }

    fn output_size() -> usize {
        sha2::Sha256::output_size()
    }

    fn digest(data: &[u8]) -> Output<Self> {
        sha2::Sha256::digest(data)
    }
}
