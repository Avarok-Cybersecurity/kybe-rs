//! Public Key Encryption
//!
//! Structure that handles all the parameters and functions required to perform the PKE

use crate::functions::{
    compress::*,
    encode::*,
    ntt::*,
    utils::{cbd, g, parse, prf, xof},
};
use crate::structures::{
    algebraics::{FiniteRing, RingModule},
    ByteArray, PolyMatrix3329, PolyVec3329,
};
use crate::Error;

use crate::structures::bytearray::SafeSplit;

/// Default length used for XOF
const XOF_LEN: usize = 4000;

#[derive(Clone, Copy)]
pub struct PKE<const N: usize, const K: usize> {
    eta: (usize, usize),
    q: usize,
    pub d: (usize, usize),
}

impl<const N: usize, const K: usize> PKE<N, K> {
    /// Kyber CPAPKE Key Generation => (secret key, public key)
    /// Algorithm 4 p. 9
    pub fn keygen(&self) -> Result<(ByteArray, ByteArray), Error> {
        let d = ByteArray::random(32);
        let (rho, sigma) = g(&d)?;
        let eta_1 = self.eta.0;

        let mut a = PolyMatrix3329::init();

        for i in 0..K {
            for j in 0..K {
                a.set(i, j, parse(&xof(&rho, j, i, XOF_LEN), self.q));
            }
        }

        let (mut s, mut e) = (PolyVec3329::<N, K>::init(), PolyVec3329::<N, K>::init());
        let prf_len = 64 * eta_1;

        for i in 0..K {
            s.set(i, cbd(prf(&sigma, i, prf_len), eta_1)?);
            e.set(i, cbd::<N>(prf(&sigma, K + i, prf_len), eta_1)?);
        }
        let s_hat = ntt_vec(&s);
        let e_hat = ntt_vec(&e);

        let t_hat = bcm_matrix_vec(&a, &s_hat).add(&e_hat);

        let mut pk = encode_polyvec(t_hat, 12);
        pk.append(&rho);

        let sk = encode_polyvec(s_hat, 12);

        Ok((sk, pk))
    }

    /// Kyber CPAPKE Encryption : public key, message, random coins => ciphertext
    /// Algorithm 5 p. 10
    pub fn encrypt<T: AsRef<[u8]>, R: AsRef<[u8]>, V: AsRef<[u8]>>(
        &self,
        pk: T,
        m: R,
        r: V,
    ) -> Result<ByteArray, Error> {
        let pk = pk.as_ref();
        let m = m.as_ref();
        let r = r.as_ref();

        let offset = 12 * K * N / 8;
        let (eta_1, eta_2) = self.eta;
        let (du, dv) = self.d;

        let (t, rho) = pk.safe_split_at(offset)?;
        let t_hat = decode_to_polyvec(t, 12)?;
        let mut a_t = PolyMatrix3329::init();
        let prf1_len = 64 * eta_1;
        let prf2_len = 64 * eta_2;

        for i in 0..K {
            for j in 0..K {
                a_t.set(i, j, parse(&xof(&rho, i, j, XOF_LEN), self.q));
            }
        }

        let (mut r_bold, mut e1) = (PolyVec3329::<N, K>::init(), PolyVec3329::<N, K>::init());
        for i in 0..K {
            r_bold.set(i, cbd(prf(&r, i, prf1_len), eta_1)?);
            e1.set(i, cbd(prf(&r, K + i, prf2_len), eta_2)?);
        }
        let e2 = cbd(prf(&r, 2 * K, prf2_len), eta_2)?;

        let r_hat = ntt_vec(&r_bold);
        let u_bold = ntt_product_matvec(&a_t, &r_hat).add(&e1);

        let x = decode_to_poly::<N, _>(m, 1)?;
        println!("Mapping {:?} to degree={:?}, coefficients={:?}", m, x.degree, x.coefficients);


        let v = ntt_product_vec(&t_hat, &r_hat)
            .add(&e2)
            .add(&decompress_poly(
                x,
                1,
                self.q,
            ));

        let mut c1 = encode_polyvec(compress_polyvec(u_bold, du, self.q), du);
        let c2 = encode_poly(compress_poly(v, dv, self.q), dv, false);

        c1.append(&c2);

        Ok(c1)
    }

    /// Kyber CPAPKE Decryption : secret key, ciphertext => message
    /// Algorithm 6 p. 10
    pub fn decrypt<T: AsRef<[u8]>, R: AsRef<[u8]>>(&self, sk: T, c: R) -> Result<ByteArray, Error> {
        let sk = sk.as_ref();
        let c = c.as_ref();

        let (du, dv) = self.d;

        let offset = du * K * N / 8;
        let (c1, c2) = c.safe_split_at(offset)?;

        let u = decompress_polyvec(decode_to_polyvec::<N, K, _>(c1, du)?, du, self.q);
        let v = decompress_poly(decode_to_poly(c2, dv)?, dv, self.q);
        let s = decode_to_polyvec(sk.clone(), 12)?;

        let m = v.sub(&ntt_product_vec(&s, &ntt_vec(&u)));

        let ret = encode_poly(compress_poly(m, 1, self.q), 1, true);
        println!("ret.len = {} || c1.len = {} || c2.len = {}", ret.as_ref().len(), c1.len(), c2.len());
        Ok(ret)
    }

    pub const fn init(q: usize, eta: (usize, usize), d: (usize, usize)) -> Self {
        Self { eta, q, d }
    }
}

#[test]
fn pke_keygen_cpapke_512() {
    let pke = crate::kyber512pke();
    pke.keygen().unwrap();
}

#[test]
fn pke_keygen_cpapke_768() {
    let pke = crate::kyber768pke();
    pke.keygen().unwrap();
}

#[test]
fn encrypt_then_decrypt_cpapke_512() {
    let pke = crate::kyber512pke();
    let (sk, pk) = pke.keygen().unwrap();

    let m = ByteArray::random(32);
    let r = ByteArray::random(32);

    let enc = pke.encrypt(&pk, &m, &r).unwrap();
    let dec = pke.decrypt(&sk, &enc).unwrap();

    assert_eq!(m, dec);
}

#[test]
fn encrypt_then_decrypt_cpapke_512_fail() {
    let pke = crate::kyber512pke();
    let (mut sk, pk) = pke.keygen().unwrap();

    let m = ByteArray::random(32);
    let r = ByteArray::random(32);

    let enc = pke.encrypt(&pk, &m, &r).unwrap();

    // alter the SK's first byte
    sk.data[0] = sk.data[0].wrapping_add(1);
    let dec = pke.decrypt(&sk, &enc).unwrap();

    assert_ne!(m, dec);
}

#[test]
fn encrypt_then_decrypt_cpapke_512_fail2() {
    let pke = crate::kyber512pke();
    let (sk, pk) = pke.keygen().unwrap();

    let m = ByteArray::random(32);
    let r = ByteArray::random(32);

    let mut enc = pke.encrypt(&pk, &m, &r).unwrap();

    // alter the enc's first byte
    let len = enc.data.len();
    enc.data[len - 1] = enc.data[len - 1].wrapping_add(200);
    let dec = pke.decrypt(&sk, &enc).unwrap();

    assert_ne!(m, dec);
}

#[test]
fn encrypt_then_decrypt_cpapke_768() {
    let pke = crate::kyber768pke();
    let (sk, pk) = pke.keygen().unwrap();

    let m = ByteArray::random(32);
    let r = ByteArray::random(32);

    let enc = pke.encrypt(&pk, &m, &r).unwrap();
    let dec = pke.decrypt(&sk, &enc).unwrap();

    assert_eq!(m, dec);
}

#[test]
fn encrypt_then_decrypt_cpapke_768_fail() {
    let pke = crate::kyber768pke();
    let (mut sk, pk) = pke.keygen().unwrap();

    let m = ByteArray::random(32);
    let r = ByteArray::random(32);

    let enc = pke.encrypt(&pk, &m, &r).unwrap();

    // alter the SK's first byte
    sk.data[0] = sk.data[0].wrapping_add(1);
    let dec = pke.decrypt(&sk, &enc).unwrap();

    assert_ne!(m, dec);
}

#[test]
fn encrypt_then_decrypt_cpapke_768_fail2() {
    let pke = crate::kyber768pke();
    let (sk, pk) = pke.keygen().unwrap();

    let m = ByteArray::random(32);
    let r = ByteArray::random(32);

    let mut enc = pke.encrypt(&pk, &m, &r).unwrap();

    // alter the enc's first byte
    let len = enc.data.len();
    enc.data[len - 1] = enc.data[len - 1].wrapping_add(200);
    let dec = pke.decrypt(&sk, &enc).unwrap();

    assert_ne!(m, dec);
}

#[test]
fn encrypt_then_decrypt_cpapke_1024() {
    let pke = crate::kyber1024pke();
    let (sk, pk) = pke.keygen().unwrap();

    let m = ByteArray::random(32);
    let r = ByteArray::random(32);

    let enc = pke.encrypt(&pk, &m, &r).unwrap();
    let dec = pke.decrypt(&sk, &enc).unwrap();

    assert_eq!(m, dec);
}

#[test]
fn encrypt_then_decrypt_cpapke_1024_fail() {
    let pke = crate::kyber1024pke();
    let (mut sk, pk) = pke.keygen().unwrap();

    let m = ByteArray::random(32);
    let r = ByteArray::random(32);

    let enc = pke.encrypt(&pk, &m, &r).unwrap();

    // alter the SK's first byte
    sk.data[0] = sk.data[0].wrapping_add(1);
    let dec = pke.decrypt(&sk, &enc).unwrap();

    assert_ne!(m, dec);
}
