use parity_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt;
#[cfg(feature = "bech32")]
use std::str::FromStr;

use crate::common::H256;
#[cfg(feature = "bech32")]
use crate::init::address::{CroAddress, CroAddressError};
#[cfg(feature = "bech32")]
use bech32::{self, u5, FromBase32, ToBase32};

#[cfg(feature = "bech32")]
use crate::init::network::get_bech32_human_part;

/// TODO: opaque types?
type TreeRoot = H256;

/// Currently, only Ethereum-style redeem address + MAST of Or operations (records the root).
/// TODO: HD-addresses?
/// TODO: custom Encode/Decode when data structures are finalized (for backwards/forwards compatibility, encoders/decoders should be able to work with old formats)
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ExtendedAddr {
    OrTree(TreeRoot),
}

#[cfg(feature = "bech32")]
impl ExtendedAddr {
    fn get_string(&self, hash: TreeRoot) -> String {
        let checked_data: Vec<u5> = hash.to_vec().to_base32();

        bech32::encode(get_bech32_human_part(), checked_data)
            .expect("bech32 should be successful in ExtendedAddr get_string")
    }
}

#[cfg(feature = "bech32")]
impl CroAddress<ExtendedAddr> for ExtendedAddr {
    fn to_cro(&self) -> Result<String, CroAddressError> {
        match self {
            ExtendedAddr::OrTree(hash) => {
                let encoded = self.get_string(*hash);
                Ok(encoded.to_string())
            }
        }
    }

    fn from_cro(encoded: &str) -> Result<Self, CroAddressError> {
        bech32::decode(encoded)
            .map_err(|e| CroAddressError::Bech32Error(e.to_string()))
            .and_then(|a| Vec::from_base32(&a.1).map_err(|_e| CroAddressError::ConvertError))
            .and_then(|src| {
                let mut a: TreeRoot = [0 as u8; 32];
                a.copy_from_slice(&src.as_slice());
                Ok(ExtendedAddr::OrTree(a))
            })
    }
}

#[cfg(feature = "bech32")]
impl fmt::Display for ExtendedAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_cro().unwrap())
    }
}

#[cfg(not(feature = "bech32"))]
impl fmt::Display for ExtendedAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtendedAddr::OrTree(hash) => write!(f, "0x{}", hex::encode(hash)),
        }
    }
}

#[cfg(feature = "bech32")]
impl FromStr for ExtendedAddr {
    type Err = CroAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ExtendedAddr::from_cro(s).map_err(|_e| CroAddressError::ConvertError)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn should_be_correct_textual_address() {
        let mut ar = [0; 32];
        ar.copy_from_slice(
            &hex::decode("0e7c045110b8dbf29765047380898919c5cb56f400112233445566778899aabb")
                .unwrap(),
        );
        let a = ExtendedAddr::OrTree(ar);
        let b = a.to_cro().unwrap();
        assert_eq!(
            b,
            "crmt1pe7qg5gshrdl99m9q3ecpzvfr8zuk4h5qqgjyv6y24n80zye42asr8c7xt"
        );
        let c = ExtendedAddr::from_cro(&b).unwrap();
        assert_eq!(c, a);
    }

    #[test]
    fn shoule_be_correct_hex_address() {
        let mut ar = [0; 32];
        ar.copy_from_slice(
            &hex::decode("0e7c045110b8dbf29765047380898919c5cb56f400112233445566778899aabb")
                .unwrap(),
        );
        let a = ExtendedAddr::OrTree(ar);
        let b = ExtendedAddr::from_str(
            "crmt1pe7qg5gshrdl99m9q3ecpzvfr8zuk4h5qqgjyv6y24n80zye42asr8c7xt",
        )
        .unwrap();
        assert_eq!(a, b);
    }
}
