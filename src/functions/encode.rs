//! Encode/Decode functions
//!
//! Utils to serialize/deserialize polynomial and polyvec

use crate::structures::{
    algebraics::{FiniteField, RingModule},
    ByteArray, Poly3329, PolyVec3329, F3329,
};
use crate::Error;

use crate::structures::bytearray::GetBit;
use crate::structures::bytearray::SafeSplit;

/// Deserialize ByteArray into Polynomial
/// Algorithm 3 p. 8
pub fn decode_to_poly<const N: usize, T: AsRef<[u8]>>(bs: T, ell: usize) -> Poly3329<N> {
    let mut f = [F3329::zero(); N];

    for i in 0..N {
        for j in 0..ell {
            if bs.get_bit(i * ell + j) {
                f[i] = f[i].add(&F3329::from_int(1 << j));
            }
        }
    }
    Poly3329::from_vec(f)
}

/// Serialize Poly into ByteArray
pub fn encode_poly<const N: usize>(p: Poly3329<N>, ell: usize) -> ByteArray {
    let mut b = vec![];
    let mut c: u8 = 0;

    for i in 0..256 {
        let mut v = p[i].to_int();
        for j in 0..ell {
            let s = (i * ell + j) % 8;
            if s == 0 && !(i == 0 && j == 0) {
                b.push(c);
                c = 0;
            }
            if (v & 1) == 1 {
                let a = 1 << s;
                c += a as u8;
            }
            v >>= 1;
        }
    }
    b.push(c);

    ByteArray { data: b }
}

/// Deserialize ByteArray into PolyVec
pub fn decode_to_polyvec<const N: usize, const D: usize, T: AsRef<[u8]>>(
    bs: T,
    ell: usize,
) -> Result<PolyVec3329<N, D>, Error> {
    let mut bs = bs.as_ref();
    let mut p_vec = PolyVec3329::from_vec([Poly3329::init(); D]);

    let mut init_split_pt = 0;
    for i in 0..D {
        let (_, c) = bs.safe_split_at(init_split_pt)?;
        let (a, _) = c.safe_split_at(32 * ell)?;
        p_vec.set(i, decode_to_poly(a, ell));
        init_split_pt += (32 * ell);
    }

    Ok(p_vec)
}

/*pub fn decode_to_polyvec<const N: usize, const D: usize, T: AsRef<[u8]>>(
    bs: T,
    ell: usize,
) -> Result<PolyVec3329<N, D>, Error> {
    let bs = bs.as_ref();
    //let k = bs.data.len() / (32 * ell);
    let mut b = bs.to_vec();
    let mut p_vec = PolyVec3329::from_vec([Poly3329::init(); D]);

    for i in 0..D {
        let (a, c) = b.safe_split_at(32 * ell)?;
        p_vec.set(i, decode_to_poly(a, ell));
        b = c.to_vec();
    }

    Ok(p_vec)
}*/

/// Serialize PolyVec into ByteArray
pub fn encode_polyvec<const N: usize, const D: usize>(
    p_vec: PolyVec3329<N, D>,
    s: usize,
) -> ByteArray {
    let mut b = ByteArray::new();

    for i in 0..D {
        let p = p_vec.get(i);
        b.append(&encode_poly(p, s));
    }

    b
}

#[test]
fn encode_decode_poly() {
    let original = Poly3329::from_vec([Default::default(); 256]);
    let encoded = encode_poly(original.clone(), 12);
    let decoded = decode_to_poly(encoded, 12);
    assert!(decoded == original);
}
