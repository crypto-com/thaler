use crate::state::account::{Nonce, StakedStateAddress, StakedStateOpAttributes};
use crate::tx::TransactionId;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

use serde::{Deserialize, Serialize};

use std::fmt;

/// Unjails an account
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct UnjailTx {
    /// the expected nonce on the corresponding state
    pub nonce: Nonce,
    /// the expected address on the corresponding state
    pub address: StakedStateAddress,
    /// the versioning and network identifier
    pub attributes: StakedStateOpAttributes,
}

impl Decode for UnjailTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let nonce = Nonce::decode(input)?;
        let address = StakedStateAddress::decode(input)?;
        let attributes = StakedStateOpAttributes::decode(input)?;

        Ok(UnjailTx {
            nonce,
            address,
            attributes,
        })
    }
}

impl Encode for UnjailTx {
    fn encode_to<EncOut: Output>(&self, dest: &mut EncOut) {
        dest.push(&self.nonce);
        dest.push(&self.address);
        dest.push(&self.attributes);
    }

    fn size_hint(&self) -> usize {
        self.nonce.size_hint() + self.address.size_hint() + self.attributes.size_hint()
    }
}

impl TransactionId for UnjailTx {}

impl UnjailTx {
    /// constructs a new unjail transaction from the provided components
    #[inline]
    pub fn new(
        nonce: Nonce,
        address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
    ) -> Self {
        Self {
            nonce,
            address,
            attributes,
        }
    }
}

impl fmt::Display for UnjailTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "unjailed: {} (nonce: {})", self.address, self.nonce)?;
        write!(f, "")
    }
}
