//! # Extended Key for HD-wallet
//! adapted from https://github.com/jjyr/hdwallet (HDWallet)
//! Copyright (c) 2018 - 2020, Jiang Jinyang (licensed under the MIT License)
//! Modifications Copyright (c) 2018 - 2020, Foris Limited (licensed under the Apache License, Version 2.0)
//!

use crate::hd_wallet::KeyIndex;
use chain_core::init::network::{get_bip44_coin_type_from_network, Network};
use std::fmt;

const MASTER_SYMBOL: &str = "m";
const HARDENED_SYMBOLS: [&str; 2] = ["H", "'"];
const SEPARATOR: char = '/';

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
/// Error category
pub enum Error {
    /// invalid error
    Invalid,
    /// blank error
    Blank,
    /// key index range error
    KeyIndexOutOfRange,
}

/// ChainPath is used to describe BIP-32 KeyChain path.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainPath(String);

impl ChainPath {
    /// An SubPath iterator over the ChainPath from Root to child keys.
    pub fn iter(&self) -> impl Iterator<Item = Result<SubPath, Error>> + '_ {
        Iter(self.0.split_terminator(SEPARATOR))
    }

    /// make string
    pub fn into_string(self) -> String {
        self.0
    }

    /// Convert ChainPath to &str represent format
    pub fn to_string(&self) -> &str {
        &self.0
    }

    /// encode ChainPath to vec<u8>
    pub fn encode(self) -> Vec<u8> {
        let s = self.into_string();
        s.into_bytes()
    }

    /// get ChainPath from Vec<u8>
    pub fn decode(data: Vec<u8>) -> Result<Self, Error> {
        let s = String::from_utf8(data).map_err(|_| Error::Invalid)?;
        Ok(Self(s))
    }

    /// Returns the bip44 hd path
    pub fn create_bip44(network: Network, account_index: u32, index: u32) -> Self {
        let coin_type = get_bip44_coin_type_from_network(network);

        let chain_path_string = format!("m/44'/{}'/{}'/0/{}", coin_type, account_index, index);
        Self::from(chain_path_string)
    }
}

#[derive(Debug, PartialEq, Eq)]
/// subpath of chain path
pub enum SubPath {
    /// root of subpath
    Root,
    /// child of subpath
    Child(KeyIndex),
}

/// iterator
pub struct Iter<'a, I: Iterator<Item = &'a str>>(I);

impl<'a, I: Iterator<Item = &'a str>> Iterator for Iter<'a, I> {
    type Item = Result<SubPath, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|sub_path| {
            if sub_path == MASTER_SYMBOL {
                return Ok(SubPath::Root);
            }
            if sub_path.is_empty() {
                return Err(Error::Blank);
            }
            let last_char = &sub_path[(sub_path.len() - 1)..];
            let is_hardened = HARDENED_SYMBOLS.contains(&last_char);
            let key_index = {
                let key_index_result = if is_hardened {
                    sub_path[..sub_path.len() - 1]
                        .parse::<u32>()
                        .map_err(|_| Error::Invalid)
                        .and_then(|index| {
                            KeyIndex::hardened_from_normalize_index(index)
                                .map_err(|_| Error::KeyIndexOutOfRange)
                        })
                } else {
                    sub_path[..]
                        .parse::<u32>()
                        .map_err(|_| Error::Invalid)
                        .and_then(|index| {
                            KeyIndex::from_index(index).map_err(|_| Error::KeyIndexOutOfRange)
                        })
                };
                key_index_result?
            };
            Ok(SubPath::Child(key_index))
        })
    }
}

impl From<String> for ChainPath {
    fn from(path: String) -> Self {
        ChainPath(path)
    }
}

impl From<&str> for ChainPath {
    fn from(path: &str) -> Self {
        ChainPath(path.to_string())
    }
}

impl fmt::Display for ChainPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_path() {
        assert_eq!(
            ChainPath::from("m".to_string())
                .iter()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![SubPath::Root]
        );
        assert_eq!(
            ChainPath::from("m/1".to_string())
                .iter()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![SubPath::Root, SubPath::Child(KeyIndex::Normal(1))],
        );
        assert_eq!(
            ChainPath::from("m/2147483649H/1".to_string())
                .iter()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![
                SubPath::Root,
                SubPath::Child(KeyIndex::hardened_from_normalize_index(1).unwrap()),
                SubPath::Child(KeyIndex::Normal(1))
            ],
        );
        // alternative hardened key represent
        assert_eq!(
            ChainPath::from("m/2147483649'/1".to_string())
                .iter()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![
                SubPath::Root,
                SubPath::Child(KeyIndex::hardened_from_normalize_index(1).unwrap()),
                SubPath::Child(KeyIndex::Normal(1))
            ],
        );
        // from invalid string
        assert!(ChainPath::from("m/2147483649h/1".to_string())
            .iter()
            .collect::<Result<Vec<_>, _>>()
            .is_err());
        assert!(ChainPath::from("/2147483649H/1".to_string())
            .iter()
            .collect::<Result<Vec<_>, _>>()
            .is_err());
        assert!(ChainPath::from("a".to_string())
            .iter()
            .collect::<Result<Vec<_>, _>>()
            .is_err());
    }
}
