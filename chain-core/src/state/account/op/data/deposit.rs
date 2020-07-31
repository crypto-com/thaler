use crate::state::account::address::StakedStateAddress;
use crate::state::account::op::data::attribute::StakedStateOpAttributes;
use crate::tx::data::input::TxoPointer;
use crate::tx::TransactionId;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::prelude::v1::Vec;

/// Each input is 34 bytes
///
/// Assuming maximum inputs allowed are 64,
/// So, maximum deposit transaction size (34 * 64) + 21 (address) + 1 (attributes) = 2198 bytes
const MAX_DEPOSIT_TX_SIZE: usize = 2200; // 2200 bytes

/// takes UTXOs inputs, deposits them in the specified StakedState's bonded amount - fee
/// (updates StakedState's bonded + nonce)
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct DepositBondTx {
    /// previous transaction outputs to spend
    pub inputs: Vec<TxoPointer>,
    /// which (staking) state to deposit to
    pub to_staked_account: StakedStateAddress,
    /// versioning info etc.
    pub attributes: StakedStateOpAttributes,
}

impl Decode for DepositBondTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let size = input
            .remaining_len()?
            .ok_or_else(|| "Unable to calculate size of input")?;

        if size > MAX_DEPOSIT_TX_SIZE {
            return Err("Input too large".into());
        }

        let inputs = <Vec<TxoPointer>>::decode(input)?;
        let to_staked_account = StakedStateAddress::decode(input)?;
        let attributes = StakedStateOpAttributes::decode(input)?;

        Ok(DepositBondTx {
            inputs,
            to_staked_account,
            attributes,
        })
    }
}

impl Encode for DepositBondTx {
    fn encode_to<EncOut: Output>(&self, dest: &mut EncOut) {
        dest.push(&self.inputs);
        dest.push(&self.to_staked_account);
        dest.push(&self.attributes);
    }

    fn size_hint(&self) -> usize {
        self.inputs.size_hint() + self.to_staked_account.size_hint() + self.attributes.size_hint()
    }
}

impl TransactionId for DepositBondTx {}

impl DepositBondTx {
    /// create a new tx
    pub fn new(
        inputs: Vec<TxoPointer>,
        to_staked_account: StakedStateAddress,
        attributes: StakedStateOpAttributes,
    ) -> Self {
        DepositBondTx {
            inputs,
            to_staked_account,
            attributes,
        }
    }
}

impl fmt::Display for DepositBondTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for input in self.inputs.iter() {
            writeln!(f, "-> {}", input)?;
        }
        writeln!(f, "   {} (bonded) ->", self.to_staked_account)?;
        write!(f, "")
    }
}
