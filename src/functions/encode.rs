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
pub fn decode_to_poly<const N: usize, T: AsRef<[u8]>>(
    bs: T,
    ell: usize,
) -> Result<Poly3329<N>, Error> {
    let mut f = [F3329::zero(); N];

    let mut degree = 0;

    for i in 0..N {
        for j in 0..ell {
            let mut pos = (i * ell) + j;
            if bs.as_ref() == &[2] {
                println!("STATS: i={i}, j={j}, pos={pos}, ell={ell}")
            }
            if let Ok(true) = bs.get_bit(pos) {
                f[i] = f[i].add(&F3329::from_int(1 << j));
                degree += 1;
            }
        }
    }

    println!("degree = {degree}");

    Ok(Poly3329::from_vec(degree, f))
}

/// Serialize Poly into ByteArray
pub fn encode_poly<const N: usize>(p: Poly3329<N>, ell: usize, trim: bool) -> ByteArray {
    // TODO: in-place
    let mut b = vec![];
    let mut c: u8 = 0;

    let len = div_ceil(p.degree.unwrap_or(0), 8);

    'outer: for i in 0..N {
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

    println!("Ret = {:?} | p.degree = {:?}, p.coeffients = {:?}", b, p.degree, p.coefficients);
    println!("Suspected len = {}", len);

    if trim {
        b.truncate(len);
    }

    ByteArray { data: b }
}

fn div_ceil(a: usize, b: usize) -> usize {
    (a + b - 1) / b
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
        p_vec.set(i, decode_to_poly(a, ell)?);
        init_split_pt += 32 * ell;
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
        b.append(&encode_poly(p, s, false));
    }

    b
}

#[test]
fn encode_decode_poly() {
    let original = Poly3329::from_vec(0, [Default::default(); 256]);
    let encoded = encode_poly(original.clone(), 12, false);
    let decoded = decode_to_poly(encoded, 12).unwrap();
    assert!(decoded == original);
}
