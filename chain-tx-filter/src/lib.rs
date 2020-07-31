mod filter;
use chain_core::common::TendermintEventKey;
use filter::Bloom;
use filter::H2048;
use secp256k1::key::PublicKey;
use std::convert::TryFrom;
use std::prelude::v1::Vec;

/// Probabilistic fixed-size filter wrapper
#[derive(Default, Debug)]
pub struct BlockFilter {
    // may be replaced with GCS, e.g. https://github.com/dac-gmbh/golomb-set
    bloom: Bloom,
    modified: bool,
}

impl BlockFilter {
    /// resets the filter
    pub fn reset(&mut self) {
        self.modified = false;
        self.bloom.reset();
    }

    /// joins with another filter
    pub fn add_filter(&mut self, other: &BlockFilter) {
        self.modified = true;
        self.bloom.add(&other.bloom);
    }

    /// adds a view key to the filter
    pub fn add_view_key(&mut self, view_key: &PublicKey) {
        self.modified = true;
        self.bloom.set(&view_key.serialize()[..]);
    }

    /// gets a Key-Value payload for tendermint events
    pub fn get_tendermint_kv(&self) -> (Vec<u8>, Vec<u8>) {
        (TendermintEventKey::EthBloom.into(), self.bloom.data())
    }

    /// tests if a view key is in the filter
    /// true = maybe present
    /// false = not present
    pub fn check_view_key(&self, view_key: &PublicKey) -> bool {
        self.bloom.check(&view_key.serialize())
    }

    /// check if view keys were added since its creation
    pub fn is_modified(&self) -> bool {
        self.modified
    }

    /// gets raw filter data
    pub fn get_raw(&self) -> H2048 {
        self.bloom.raw_data()
    }
}

impl TryFrom<&[u8]> for BlockFilter {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bloom = Bloom::try_from(value)?;
        Ok(BlockFilter {
            bloom,
            modified: false,
        })
    }
}

impl From<&H2048> for BlockFilter {
    fn from(val: &H2048) -> BlockFilter {
        let bloom = Bloom::from(val);
        BlockFilter {
            bloom,
            modified: false,
        }
    }
}
