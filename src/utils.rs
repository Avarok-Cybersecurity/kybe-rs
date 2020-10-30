use std::convert::TryInto;

use crate::{hash, ByteArray, Poly3329, F3329};

////////////////// Utils ////////////////////

/// Receives as input a byte stream B=(b0; b1; b2;...) and computes the NTT-representation a' = a'_0 + a'_0X + ... + a'_n-1X^(n-1) in R_q of a in R_q
/// Algorithm 1 p. 7
pub fn parse(bs: ByteArray, n: usize, q: usize) -> Poly3329 {
    let mut i = 0;
    let mut j = 0;
    let mut coeffs = vec![F3329::default(); n];
    while j < n {
        let d = (bs.data[i] as usize) + (bs.data[i + 1] as usize) << 8;
        if d < 19 * q {
            coeffs[j] = F3329::from_int(d.try_into().unwrap());
            j += 1;
        }
        i += 2;
    }
    Poly3329::from_vec(coeffs, n)
}

/// Centered Binomial Distribution
/// Algorithm 2 p. 8
/// Takes as input an array of 64 eta bytes
pub fn cbd(bs: ByteArray, eta: usize) -> Poly3329 {
    let mut f_coeffs = vec![F3329::default(); 256];
    for i in 0..256 {
        let mut a = 0;
        let mut b = 0;

        for j in 0..eta {
            if bs.get_bit(2 * i * eta + j) {
                a += 1;
            }
            if bs.get_bit(2 * i * eta + eta + j) {
                b += 1;
            }
        }

        f_coeffs[i] = F3329::from_int(a - b);
    }
    Poly3329::from_vec(f_coeffs, 256)
}

/// Pseudo random function => SHAKE-256(s||b);
pub fn prf(s: &ByteArray, b: usize, len: usize) -> ByteArray {
    let b_as_bytes = ByteArray {
        data: (b as u64).to_be_bytes().to_vec(),
    };
    let input = ByteArray::concat(&[s, &b_as_bytes]);
    ByteArray {
        data: hash::shake_256(input.data, len),
    }
}

/// Extendable output function => SHAKE-128(rho||j||i) with output of lenght len
pub fn xof(r: &ByteArray, i: usize, j: usize, len: usize) -> ByteArray {
    let i_as_bytes = ByteArray {
        data: (i as u64).to_be_bytes().to_vec(),
    };
    let j_as_bytes = ByteArray {
        data: (j as u64).to_be_bytes().to_vec(),
    };

    let input = ByteArray::concat(&[r, &i_as_bytes, &j_as_bytes]);
    ByteArray {
        data: hash::shake_128(input.data, len),
    }
}

/// Hash function => SHA3-256
pub fn h(r: &ByteArray) -> (ByteArray, ByteArray) {
    let hash = hash::sha3_256(r.data.clone());
    let (part0, part1) = hash.split_at(16);

    (
        ByteArray {
            data: part0.to_vec(),
        },
        ByteArray {
            data: part1.to_vec(),
        },
    )
}

/// Hash function => SHA3-512
pub fn g(r: ByteArray) -> (ByteArray, ByteArray) {
    let hash = hash::sha3_512(r.data);
    let (part0, part1) = hash.split_at(32);

    (
        ByteArray {
            data: part0.to_vec(),
        },
        ByteArray {
            data: part1.to_vec(),
        },
    )
}

/// Key Derivation function => SHAKE-256
pub fn kdf(r: &ByteArray, len: usize) -> ByteArray {
    let hash = hash::shake_256(r.data.clone(), len);

    ByteArray { data: hash }
}
