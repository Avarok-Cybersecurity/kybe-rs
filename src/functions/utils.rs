//! Utils
//!
//! Various utils functions defined for the KEM anf PKE algorithms
use crate::{
    functions::hash,
    structures::{algebraics::FiniteField, ByteArray, Poly3329, F3329},
    Error,
};

use crate::structures::bytearray::GetBit;
use crate::structures::bytearray::SafeSplit;

/// Receives as input a byte stream B=(b0; b1; b2;...) and computes the NTT-representation a' = a'_0 + a'_0X + ... + a'_n-1X^(n-1) in R_q of a in R_q
/// Algorithm 1 p. 7
pub fn parse<const N: usize>(bs: &ByteArray, q: usize) -> Poly3329<N> {
    let mut i = 0;
    let mut j = 0;
    let mask = 15;

    let mut p = Poly3329::init();

    while j < N {
        let d_1 = (bs.data[i] as usize) + (((bs.data[i + 1] & mask) as usize) << 8);
        let d_2 = ((bs.data[i + 1] >> 4) as usize) + ((bs.data[i + 2] as usize) << 4);
        if d_1 < q {
            p.set_coeff(j, F3329::from_int(d_1));
            j += 1;
        }
        if d_2 < q && j < N {
            p.set_coeff(j, F3329::from_int(d_2));
            j += 1;
        }
        i += 3;
    }

    p
}

/// Centered Binomial Distribution
/// Algorithm 2 p. 8
/// Takes as input an array of 64 eta bytes
pub fn cbd<const N: usize>(bs: ByteArray, eta: usize) -> Result<Poly3329<N>, Error> {
    let mut p = Poly3329::init();
    for i in 0..N {
        let mut a = 0;
        let mut b = 0;

        for j in 0..eta {
            if bs.get_bit((2 * i * eta) + j)? {
                a += 1;
            }
            if bs.get_bit((2 * i * eta) + eta + j)? {
                b += 1;
            }
        }
        let (a_hat, b_hat) = (F3329::from_int(a), F3329::from_int(b));
        p.set_coeff(i, a_hat.sub(&b_hat));
    }

    Ok(p)
}

/// Pseudo random function => SHAKE-256(s||b);
pub fn prf<T: AsRef<[u8]>>(s: T, b: usize, len: usize) -> ByteArray {
    let b_as_bytes = &(b as u64).to_be_bytes() as &[u8];
    let input = ByteArray::concat(&[s.as_ref(), b_as_bytes]);

    ByteArray {
        data: hash::shake_256(&input.data, len),
    }
}

/// Extendable output function => SHAKE-128(rho||j||i) with output of length len
pub fn xof<T: AsRef<[u8]>>(r: T, i: usize, j: usize, len: usize) -> ByteArray {
    let i_as_bytes = &(i as u64).to_be_bytes() as &[u8];
    let j_as_bytes = &(j as u64).to_be_bytes() as &[u8];
    let input = ByteArray::concat(&[r.as_ref(), i_as_bytes, j_as_bytes]);

    ByteArray {
        data: hash::shake_128(&input.data, len),
    }
}

/// Hash function => SHA3-256
pub fn h<T: AsRef<[u8]>>(r: T) -> Result<(ByteArray, ByteArray), Error> {
    let hash = hash::sha3_256(r.as_ref());
    let (part0, part1) = hash.safe_split_at(16)?;

    Ok((ByteArray::from_bytes(part0), ByteArray::from_bytes(part1)))
}

/// Hash function => SHA3-512
pub fn g(r: &ByteArray) -> Result<(ByteArray, ByteArray), Error> {
    let hash = hash::sha3_512(&r.data);
    let (part0, part1) = hash.safe_split_at(32)?;

    Ok((ByteArray::from_bytes(part0), ByteArray::from_bytes(part1)))
}

/// Key Derivation function => SHAKE-256
pub fn kdf(r: &ByteArray, len: usize) -> ByteArray {
    let hash = hash::shake_256(&r.data, len);

    ByteArray { data: hash }
}
