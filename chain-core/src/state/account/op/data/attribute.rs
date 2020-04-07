use parity_scale_codec::{Decode, Encode, Error, Input, Output};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Serialize};

/// attributes in StakedState-related transactions
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct StakedStateOpAttributes {
    pub chain_hex_id: u8,
    pub app_version: u64,
}

impl StakedStateOpAttributes {
    pub fn new(chain_hex_id: u8) -> Self {
        StakedStateOpAttributes {
            chain_hex_id,
            app_version: crate::APP_VERSION,
        }
    }
}

impl Encode for StakedStateOpAttributes {
    fn encode_to<EncOut: Output>(&self, dest: &mut EncOut) {
        dest.push_byte(0);
        dest.push_byte(self.chain_hex_id);
        dest.push(&self.app_version);
    }

    fn size_hint(&self) -> usize {
        1 + self.chain_hex_id.size_hint() + self.app_version.size_hint()
    }
}

impl Decode for StakedStateOpAttributes {
    fn decode<DecIn: Input>(input: &mut DecIn) -> Result<Self, Error> {
        let tag = input.read_byte()?;
        if tag != 0 {
            return Err(Error::from("Unsupported TxAttributes variant"));
        }
        let chain_hex_id = input.read_byte()?;
        let app_version = u64::decode(input)?;
        Ok(StakedStateOpAttributes {
            chain_hex_id,
            app_version,
        })
    }
}
