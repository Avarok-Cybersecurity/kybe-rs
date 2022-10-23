//! Key Encapsulation Module
//!
//! Structure that handles all the parameters and functions required to perform the KEM

use crate::functions::utils::{g, h, kdf};
use crate::pke::PKE;
use crate::structures::ByteArray;
use crate::Error;

use crate::structures::bytearray::SafeSplit;

#[derive(Clone, Copy)]
pub struct KEM<const N: usize, const K: usize> {
    pke: PKE<N, K>,
    delta: usize,
    ss_size: usize,
    pk_size: usize,
    sk_size: usize,
    ct_size: usize,
}

impl<const N: usize, const K: usize> KEM<N, K> {
    /// Kyber CCAKEM Key Generation => (secret key, public key)
    /// Algorithm 7 p. 11
    pub fn keygen(&self) -> Result<(ByteArray, ByteArray), Error> {
        let z = ByteArray::random(32);

        let (sk_prime, pk) = self.pke.keygen()?;
        let (h1, h2) = h(&pk)?;
        let sk = ByteArray::concat(&[&sk_prime, &pk, &h1, &h2, &z]);

        Ok((sk, pk))
    }

    /// Encryption : public key  => ciphertext, Shared Key
    /// Algorithm 8 p. 11
    pub fn encaps(&self, pk: &ByteArray) -> Result<(ByteArray, ByteArray), Error> {
        let m = ByteArray::random(32);
        let (mut m1, m2) = h(&m)?;
        let (h1, h2) = h(pk)?;
        let (k_bar, r) = g(&ByteArray::concat(&[&m1, &m2, &h1, &h2]))?;

        m1.append(&m2);

        let c = self.pke.encrypt(pk, &m1, &r)?;

        let (h1, h2) = h(&c)?;
        let k = kdf(&ByteArray::concat(&[&k_bar, &h1, &h2]), self.sk_size);

        Ok((c, k))
    }

    /// Decryption : secret key, ciphertext => Shared Key
    /// Algorithm 9 p. 11
    pub fn decaps<T: AsRef<[u8]>, R: AsRef<[u8]>>(&self, c: T, sk: R) -> Result<ByteArray, Error> {
        // Splitting sk = (sk'||pk||H(pk)||z)
        let c = c.as_ref();
        let sk = sk.as_ref();

        let (sk_prime, rem) = sk.safe_split_at(12 * K * N / 8)?;
        let (pk, rem) = rem.safe_split_at(12 * K * N / 8 + 32)?;
        let (hash, z) = rem.safe_split_at(32)?;

        let mut m = self.pke.decrypt(&sk_prime, c)?;
        m.append(&hash);

        let (k_bar, r) = g(&m)?;
        let c_prime = self.pke.encrypt(&pk, &m, &r)?;

        let (h1, h2) = h(c)?;
        let ret = if c == c_prime.as_ref() {
            kdf(&ByteArray::concat(&[&k_bar, &h1, &h2]), self.sk_size)
        } else {
            kdf(
                &ByteArray::concat(&[z, h1.as_ref(), h2.as_ref()]),
                self.sk_size,
            )
        };

        Ok(ret)
    }

    pub const fn init(pke: PKE<N, K>, delta: usize, ss_size: usize, d: (usize, usize)) -> Self {
        let (du, dv) = d;
        Self {
            pke,
            delta,
            ss_size,
            pk_size: 12 * K * N / 8 + 32,
            sk_size: 12 * K * N / 8,
            ct_size: (du * K + dv) * N / 8,
        }
    }
}

#[test]
fn kem_keygen_ccakem_512() {
    let kem = crate::kyber512kem();
    kem.keygen().unwrap();
}

#[test]
fn kem_keygen_ccakem_768() {
    let kem = crate::kyber768kem();
    kem.keygen().unwrap();
}

#[test]
fn encapsulate_then_decapsulate_ccakem_512() {
    let kem = crate::kyber512kem();

    let (sk, pk) = kem.keygen().unwrap();
    let (ctx, shk) = kem.encaps(&pk).unwrap();
    let shk2 = kem.decaps(&ctx, &sk).unwrap();

    assert_eq!(shk, shk2);
}

#[test]
fn encapsulate_then_decapsulate_ccakem_768() {
    let kem = crate::kyber768kem();

    let (sk, pk) = kem.keygen().unwrap();
    let (ctx, shk) = kem.encaps(&pk).unwrap();
    let shk2 = kem.decaps(&ctx, &sk).unwrap();

    assert_eq!(shk, shk2);
}
