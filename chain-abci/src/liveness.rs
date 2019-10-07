use bit_vec::BitVec;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use serde::{Deserialize, Serialize};

use chain_core::state::account::StakedStateAddress;
use chain_core::state::tendermint::BlockHeight;

/// Liveness tracker for a validator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivenessTracker {
    /// Address of staking account
    address: StakedStateAddress,
    /// Holds data to measure liveness
    liveness: BitVec,
}

impl LivenessTracker {
    /// Creates a new instance of liveness tracker
    #[inline]
    pub fn new(address: StakedStateAddress, block_signing_window: u16) -> Self {
        Self {
            address,
            liveness: BitVec::from_elem(block_signing_window as usize, true),
        }
    }

    /// Updates liveness tracker with new block data
    pub fn update(&mut self, block_height: BlockHeight, signed: bool) {
        let block_signing_window = self.liveness.len();
        let update_index = (block_height as usize - 1) % block_signing_window; // Because `block_height` starts from 1
        self.liveness.set(update_index, signed)
    }

    /// Checks if validator is live or not
    #[inline]
    #[allow(dead_code)]
    pub fn is_live(&self, missed_block_threshold: u16) -> bool {
        let zero_count = self.liveness.iter().filter(|x| !x).count();
        zero_count < missed_block_threshold as usize
    }
}

impl Encode for LivenessTracker {
    fn size_hint(&self) -> usize {
        self.address.size_hint() + std::mem::size_of::<u16>() + self.liveness.to_bytes().size_hint()
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.address.encode_to(dest);
        (self.liveness.len() as u16).encode_to(dest);
        self.liveness.to_bytes().encode_to(dest);
    }
}

impl Decode for LivenessTracker {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let address = StakedStateAddress::decode(input)?;
        let length = u16::decode(input)?;
        let bytes = <Vec<u8>>::decode(input)?;

        let mut liveness = BitVec::from_bytes(&bytes);
        liveness.truncate(length as usize);

        Ok(LivenessTracker { address, liveness })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chain_core::init::address::RedeemAddress;

    #[test]
    fn check_liveness_tracker_encode_decode() {
        let address = StakedStateAddress::BasicRedeem(RedeemAddress([0; 20]));

        let mut initial = LivenessTracker::new(address, 50);
        initial.update(1, true);
        initial.update(2, false);

        let encoded = initial.encode();
        let decoded = LivenessTracker::decode(&mut encoded.as_ref()).unwrap();

        assert_eq!(initial, decoded);
    }

    #[test]
    fn check_liveness_tracker() {
        let address = StakedStateAddress::BasicRedeem(RedeemAddress([0; 20]));

        let mut tracker = LivenessTracker::new(address, 5);
        tracker.update(1, true);
        tracker.update(2, false);
        tracker.update(3, true);
        tracker.update(4, false);
        tracker.update(5, true);

        assert!(tracker.is_live(3));
        assert!(!tracker.is_live(2));
    }
}
