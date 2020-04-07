use crate::init::coin::Coin;
use crate::state::account::address::StakedStateAddress;
use crate::state::account::op::data::attribute::StakedStateOpAttributes;
use crate::state::account::Nonce;
use crate::tx::TransactionId;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Serialize};
#[cfg(not(feature = "mesalock_sgx"))]
use std::fmt;

/// updates the StakedState by moving some of the bonded amount - fee into unbonded,
/// and setting the unbonded_from to last_block_time+min_unbonding_time (network parameter)
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct UnbondTx {
    pub from_staked_account: StakedStateAddress,
    pub nonce: Nonce,
    pub value: Coin,
    pub attributes: StakedStateOpAttributes,
}

impl Decode for UnbondTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let from_staked_account = StakedStateAddress::decode(input)?;
        let nonce = Nonce::decode(input)?;
        let value = Coin::decode(input)?;
        let attributes = StakedStateOpAttributes::decode(input)?;

        Ok(UnbondTx {
            from_staked_account,
            nonce,
            value,
            attributes,
        })
    }
}

impl Encode for UnbondTx {
    fn encode_to<EncOut: Output>(&self, dest: &mut EncOut) {
        dest.push(&self.from_staked_account);
        dest.push(&self.nonce);
        dest.push(&self.value);
        dest.push(&self.attributes);
    }

    fn size_hint(&self) -> usize {
        self.from_staked_account.size_hint()
            + self.nonce.size_hint()
            + self.value.size_hint()
            + self.attributes.size_hint()
    }
}

impl TransactionId for UnbondTx {}

impl UnbondTx {
    pub fn new(
        from_staked_account: StakedStateAddress,
        nonce: Nonce,
        value: Coin,
        attributes: StakedStateOpAttributes,
    ) -> Self {
        UnbondTx {
            from_staked_account,
            nonce,
            value,
            attributes,
        }
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Display for UnbondTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} unbonded: {} (nonce: {})",
            self.from_staked_account, self.value, self.nonce
        )?;
        write!(f, "")
    }
}
