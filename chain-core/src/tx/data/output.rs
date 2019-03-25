use crate::common::Timespec;
use crate::init::coin::Coin;
use crate::tx::data::address::ExtendedAddr;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::fmt;

/// Tx Output composed of an address and a coin value
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxOut {
    pub address: ExtendedAddr,
    pub value: Coin,
    pub valid_from: Option<Timespec>,
}

impl fmt::Display for TxOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.address, self.value)
    }
}

impl Encodable for TxOut {
    fn rlp_append(&self, s: &mut RlpStream) {
        let len = if self.valid_from.is_some() { 3 } else { 2 };
        s.begin_list(len).append(&self.address).append(&self.value);
        if let Some(ts) = &self.valid_from {
            s.append(ts);
        }
    }
}

impl Decodable for TxOut {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let item_count = rlp.item_count()?;
        if !(rlp.item_count()? <= 3 && rlp.item_count()? >= 2) {
            return Err(DecoderError::Custom("Cannot decode a transaction output"));
        }
        let address: ExtendedAddr = rlp.val_at(0)?;
        let value: Coin = rlp.val_at(1)?;
        match item_count {
            2 => Ok(TxOut::new(address, value)),
            3 => {
                let ts: Timespec = rlp.val_at(2)?;
                Ok(TxOut::new_with_timelock(address, value, ts))
            }
            _ => Err(DecoderError::Custom("Unknown transaction output")),
        }
    }
}

impl TxOut {
    /// creates a TX output (mainly for testing/tools)
    pub fn new(address: ExtendedAddr, value: Coin) -> Self {
        TxOut {
            address,
            value,
            valid_from: None,
        }
    }

    /// creates a TX output with timelock
    pub fn new_with_timelock(address: ExtendedAddr, value: Coin, valid_from: Timespec) -> Self {
        TxOut {
            address,
            value,
            valid_from: Some(valid_from),
        }
    }
}
