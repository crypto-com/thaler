//! # Eth-style Bloom Filter
//! adapted from https://github.com/ETCDEVTeam/etcommon-rs (Etcommon)
//! Copyright (c) 2018, ETCDEV (licensed under the Apache License, Version 2.0)
//! Modifications Copyright (c) 2019, Foris Limited (licensed under the Apache License, Version 2.0)
//!
//! ## Ethereum Bloom filter for Logs as described in the yellow paper
//! "a specialised Bloom filter that sets three bits out of 2048,
//! given an arbitrary byte sequence. It does this through taking the low-order 11 bits of each of
//! the first three pairs of bytes in a Keccak-256 hash of the byte sequence."
use bit_vec::BitVec;
use chain_core::init::address::keccak256;

type H2048 = [u8; 256];

/// A Bloom filter
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bloom(BitVec);

impl Default for Bloom {
    fn default() -> Self {
        Bloom(BitVec::from_elem(2048, false))
    }
}

impl Into<BitVec> for Bloom {
    fn into(self) -> BitVec {
        self.0
    }
}

impl From<&H2048> for Bloom {
    fn from(val: &H2048) -> Bloom {
        Bloom(BitVec::from_bytes(&val[..]))
    }
}

impl Into<H2048> for Bloom {
    fn into(self) -> H2048 {
        let mut result = [0u8; 256];
        let bytes = self.0.to_bytes();
        result.copy_from_slice(&bytes);
        result
    }
}

fn single_set(arr: &[u8]) -> BitVec {
    let mut r = [0u8; 256];
    let h = keccak256(arr);
    for i in [0usize, 2usize, 4usize].iter() {
        let m = (((h[*i] as usize) << 8) + (h[*i + 1] as usize)) % 2048;
        r[m / 8] |= 1 << (m % 8);
    }
    BitVec::from_bytes(&r[..])
}

impl Bloom {
    /// Set respective bits in the bloom with the array
    pub fn set(&mut self, arr: &[u8]) {
        self.0.union(&single_set(arr));
    }

    /// Check that an array is in the bloom
    pub fn check(&self, arr: &[u8]) -> bool {
        let s1 = single_set(arr);
        let mut s2 = s1.clone();
        s2.intersect(&self.0);

        s2 == s1
    }

    /// Gets the bytes from the underlying bitvector
    pub fn data(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;

    #[test]
    fn test_bloom() {
        let mut bloom = Bloom::default();
        let test_vec = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6";
        let arr = hex::decode(test_vec).unwrap();
        bloom.set(&arr);
        assert!(bloom.check(&hex::decode(test_vec).unwrap()));

        let h: H2048 = bloom.into();
        for i in [1323usize, 431usize, 1319usize].iter() {
            let v = 1 << (i % 8);
            assert!(h[i / 8] & v == v);
        }
    }

    quickcheck! {

        // test this implementation matches ethbloom
        fn ethbloom_implementation_matches(bloom: Vec<u8>, test: Vec<u8>) -> bool {
            let mut b1: Bloom = Bloom::default();
            b1.set(&bloom);
            let mut b2: ethbloom::Bloom = ethbloom::Bloom::default();
            b2.accrue(ethbloom::Input::Raw(&bloom));

            b1.check(&test) == b2.contains_input(ethbloom::Input::Raw(&test))
        }

    }

}
