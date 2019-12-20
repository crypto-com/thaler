use parity_scale_codec::{Decode, Encode};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Serialize};
#[cfg(not(feature = "mesalock_sgx"))]
use std::fmt;
#[cfg(not(feature = "mesalock_sgx"))]
use std::str::FromStr;

use crate::common::H256;
#[cfg(not(feature = "mesalock_sgx"))]
use crate::init::address::{CroAddress, CroAddressError};
#[cfg(not(feature = "mesalock_sgx"))]
use bech32::{self, u5, FromBase32, ToBase32};

#[cfg(not(feature = "mesalock_sgx"))]
use crate::init::network::{get_bech32_human_part_from_network, get_network, Network};

/// TODO: opaque types?
type TreeRoot = H256;

/// Currently, only Ethereum-style redeem address + MAST of Or operations (records the root).
/// TODO: HD-addresses?
/// TODO: custom Encode/Decode when data structures are finalized (for backwards/forwards compatibility, encoders/decoders should be able to work with old formats)
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub enum ExtendedAddr {
    OrTree(TreeRoot),
}

#[cfg(not(feature = "mesalock_sgx"))]
impl CroAddress<ExtendedAddr> for ExtendedAddr {
    fn to_cro(&self, network: Network) -> Result<String, CroAddressError> {
        match self {
            ExtendedAddr::OrTree(hash) => {
                let checked_data: Vec<u5> = hash.to_vec().to_base32();
                let encoded =
                    bech32::encode(get_bech32_human_part_from_network(network), checked_data)
                        .expect("bech32 encoding error");
                Ok(encoded)
            }
        }
    }

    fn from_cro(encoded_addr: &str, network: Network) -> Result<Self, CroAddressError> {
        if !encoded_addr.starts_with(get_bech32_human_part_from_network(network)) {
            return Err(CroAddressError::InvalidNetwork);
        }

        bech32::decode(encoded_addr)
            .map_err(|e| CroAddressError::Bech32Error(e.to_string()))
            .and_then(|decoded| {
                Vec::from_base32(&decoded.1).map_err(|_e| CroAddressError::ConvertError)
            })
            .and_then(|hash| {
                let mut tree_root_hash: TreeRoot = [0 as u8; 32];
                tree_root_hash.copy_from_slice(&hash.as_slice());
                Ok(ExtendedAddr::OrTree(tree_root_hash))
            })
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Display for ExtendedAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_cro(get_network()).unwrap())
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl FromStr for ExtendedAddr {
    type Err = CroAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ExtendedAddr::from_cro(s, get_network()).map_err(|_e| CroAddressError::ConvertError)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn should_be_correct_textual_address() {
        let network = Network::Devnet;

        let mut tree_root_hash = [0; 32];
        tree_root_hash.copy_from_slice(
            &hex::decode("0e7c045110b8dbf29765047380898919c5cb56f400112233445566778899aabb")
                .unwrap(),
        );
        let extended_addr = ExtendedAddr::OrTree(tree_root_hash);
        let bech32_addr = extended_addr.to_cro(network).unwrap();
        assert_eq!(
            bech32_addr,
            "dcro1pe7qg5gshrdl99m9q3ecpzvfr8zuk4h5qqgjyv6y24n80zye42as88x8tg"
        );

        let restored_extended_addr = ExtendedAddr::from_cro(&bech32_addr, network).unwrap();
        assert_eq!(restored_extended_addr, extended_addr);
    }

    #[test]
    fn should_be_correct_hex_address() {
        let mut tree_root_hash = [0; 32];
        tree_root_hash.copy_from_slice(
            &hex::decode("0e7c045110b8dbf29765047380898919c5cb56f400112233445566778899aabb")
                .unwrap(),
        );
        let extended_addr_from_hash = ExtendedAddr::OrTree(tree_root_hash);
        let extended_addr_from_str = ExtendedAddr::from_str(
            "dcro1pe7qg5gshrdl99m9q3ecpzvfr8zuk4h5qqgjyv6y24n80zye42as88x8tg",
        )
        .unwrap();
        assert_eq!(extended_addr_from_hash, extended_addr_from_str);
    }

    mod from_cro {
        use super::*;

        #[test]
        fn should_return_invalid_network_error_when_prefix_is_incorrect() {
            let result = ExtendedAddr::from_cro(
                "dcro1pe7qg5gshrdl99m9q3ecpzvfr8zuk4h5qqgjyv6y24n80zye42as88x8tg",
                Network::Mainnet,
            );

            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), CroAddressError::InvalidNetwork);
        }

        #[test]
        fn should_work_when_prefix_is_correct() {
            let result = ExtendedAddr::from_cro(
                "dcro1pe7qg5gshrdl99m9q3ecpzvfr8zuk4h5qqgjyv6y24n80zye42as88x8tg",
                Network::Devnet,
            );

            assert!(result.is_ok());
        }
    }
}
