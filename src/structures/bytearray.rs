//! ByteArray
//!
//! ByteArray used for exchange and encoding/decoding

use crate::Error;
use rand::prelude::*;

/// A struct representing an array of bytes
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ByteArray {
    /// Array of bytes
    pub data: Vec<u8>,
}

pub struct ByteArrayRef<'a> {
    pub data: &'a [u8],
}

impl ByteArray {
    /// Generate an empty ByteArray
    pub const fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Generate a ByteArrey from a slice of bytes
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// Generate a ByteArray of size len filled with random values
    pub fn random(len: usize) -> Self {
        let mut data = vec![0; len];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut data);

        Self { data }
    }

    /// Append two ByteArrays together
    pub fn append<T: AsRef<[u8]>>(&mut self, other: T) {
        self.data.extend_from_slice(other.as_ref())
    }

    /// Append an array of ByteArrays together
    pub fn concat<T: AsRef<[u8]>>(items: &[T]) -> Self {
        let len = items.iter().map(|slice| slice.as_ref().len()).sum();
        let mut data = Vec::with_capacity(len);

        for item in items.iter() {
            data.extend_from_slice(item.as_ref());
        }

        Self { data }
    }
}

impl AsRef<[u8]> for ByteArray {
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
}

pub(crate) trait GetBit {
    fn get_bit(&self, pos: usize) -> Result<bool, Error>;
}

pub(crate) trait SafeSplit {
    fn safe_split_at(&self, pos: usize) -> Result<(&[u8], &[u8]), Error>;
}

impl<T: AsRef<[u8]>> GetBit for T {
    fn get_bit(&self, pos: usize) -> Result<bool, Error> {
        let index = pos / 8;
        let exp = pos % 8;
        let byte_value_at_index = self.as_ref().get(index).cloned().ok_or_else(|| {
            Error::Index(format!(
                "Unable to get idx {} from array of len {}",
                index,
                self.as_ref().len()
            ))
        })?;

        let ret = (byte_value_at_index >> exp) & 1;

        Ok(ret == 1)
    }
}

impl<T: AsRef<[u8]>> SafeSplit for T {
    fn safe_split_at(&self, pos: usize) -> Result<(&[u8], &[u8]), Error> {
        let this = self.as_ref();
        if pos > this.len() {
            Err(Error::Decrypt(format!("pos={pos} > len={}", this.len())))
        } else {
            Ok(this.split_at(pos))
        }
    }
}
