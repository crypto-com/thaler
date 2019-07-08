use parity_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::common::{H256, HASH_SIZE_256};
use crate::init::address::CroAddress;

use bech32::{u5, Bech32, FromBase32, ToBase32};

/// TODO: opaque types?
type TreeRoot = H256;

/// Currently, only Ethereum-style redeem address + MAST of Or operations (records the root).
/// TODO: HD-addresses?
/// TODO: custom Encode/Decode when data structures are finalized (for backwards/forwards compatibility, encoders/decoders should be able to work with old formats)
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ExtendedAddr {
    OrTree(TreeRoot),
}

impl CroAddress<ExtendedAddr> for ExtendedAddr {
    fn to_cro(&self) -> Result<String, ()> {
        match self {
            ExtendedAddr::OrTree(hash) => {
                let a = hash;
                // converts base256 data to base32 and adds padding if needed
                let checked_data: Vec<u5> = a.to_vec().to_base32();
                // CRMS: mainnet staked-state
                // CRMT: mainnet transfer
                // CRTS: testnet staked-state
                // CRTT: testnet transfer
                let b = Bech32::new("crmt".into(), checked_data).expect("hrp is not empty");
                let encoded2 = b.to_string().as_bytes().to_vec();
                //encoded2[0]='x' as u8;
                let encoded = String::from_utf8(encoded2).unwrap();
                Ok(encoded)
            }
        }
    }

    fn from_cro(encoded: &str) -> Result<Self, ()> {
        encoded
            .parse::<Bech32>()
            .map_err(|_x| ())
            .and_then(|a| match Vec::from_base32(&a.data()) {
                Ok(src) => {
                    let mut a: TreeRoot = [0 as u8; 32];
                    a.copy_from_slice(&src);
                    Ok(ExtendedAddr::OrTree(a))
                }
                Err(_b) => Err(()),
            })
    }
}

impl fmt::Display for ExtendedAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // TODO: base58 for encoding addresses
            ExtendedAddr::OrTree(hash) => write!(f, "0x{}", hex::encode(hash)),
        }
    }
}

impl FromStr for ExtendedAddr {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let address = if s.starts_with("0x") {
            s.split_at(2).1
        } else {
            s
        };

        let decoded = hex::decode(&address)?;

        if decoded.len() != HASH_SIZE_256 {
            return Err(hex::FromHexError::InvalidStringLength);
        }

        let mut tree_root = [0; HASH_SIZE_256];
        tree_root.copy_from_slice(&decoded);

        Ok(ExtendedAddr::OrTree(tree_root))
    }
}
