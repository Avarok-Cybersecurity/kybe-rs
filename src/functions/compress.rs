//! Compress/Decompress functions
//!
//! Utils for compressing/decompressing integers, polynomials and polyvec


use crate::structures::{Poly3329, PolyVec3329, F3329};

/// Compress function on coefficients, p. 6
fn compress_integer(x: u16, d: u16, q: u16) -> u16 {
    let power = 1 << d;
    let compressed = (power as f64) / (q as f64) * (x as f64);

    (compressed.round() as u16) % power
}

/// Decompress function on coefficients, p. 6
fn decompress_integer(x: u16, d: u16, q: u16) -> u16 {
    let power = 1 << d;
    let compressed = (q as f64) * (x as f64) / (power as f64);

    compressed.round() as _
}

/// Compress function on R_q
pub fn compress_poly<const N: usize>(x: Poly3329<N>, d: u16, q: u16) -> Poly3329<N> {
    let mut coeffs = [Default::default(); N];
    for (i, el) in coeffs.iter_mut().enumerate() {
        *el = F3329::from(compress_integer(x[i].as_int(), d, q));
    }
    Poly3329::from_vec(coeffs.len() - 1, coeffs)
}

/// Deompress function on R_q
pub fn decompress_poly<const N: usize>(x: Poly3329<N>, d: u16, q: u16) -> Poly3329<N> {
    let mut coeffs = [Default::default(); N];
    for (i, el) in coeffs.iter_mut().enumerate() {
        *el = F3329::from(decompress_integer(x[i].as_int(), d, q));
    }
    Poly3329::from_vec(coeffs.len() - 1, coeffs)
}

/// Compress function on R_q^k
pub fn compress_polyvec<const N: usize, const D: usize>(
    x: PolyVec3329<N, D>,
    d: u16,
    q: u16,
) -> PolyVec3329<N, D> {
    let mut coeffs = [Default::default(); D];
    for (i, el) in coeffs.iter_mut().enumerate() {
        *el = compress_poly(x.coefficients[i], d, q);
    }
    PolyVec3329::from(coeffs)
}

/// Decompress function on R_q^k
pub fn decompress_polyvec<const N: usize, const D: usize>(
    x: PolyVec3329<N, D>,
    d: u16,
    q: u16,
) -> PolyVec3329<N, D> {
    let mut coeffs = [Default::default(); D];
    for (i, el) in coeffs.iter_mut().enumerate() {
        *el = decompress_poly(x.coefficients[i], d, q);
    }
    PolyVec3329::from(coeffs)
}

#[test]
fn compress_decompress_poly() {
    let original = Poly3329::from_vec(256 - 1, [Default::default(); 256]);
    let encoded = compress_poly(original, 12, 3329);
    let decoded = decompress_poly(encoded, 12, 3329);
    assert!(decoded == original);
}
