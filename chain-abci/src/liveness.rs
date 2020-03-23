use bit_vec::BitVec;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use serde::{Deserialize, Serialize};

use chain_core::state::tendermint::BlockHeight;

/// Liveness tracker for a validator
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivenessTracker {
    /// Holds data to measure liveness
    ///
    /// # Note
    ///
    /// - Size of this `BitVec` should be equal to `block_signing_window` in jailing parameters in genesis.
    /// - Stores `true` at `index = height % block_signing_window`, if validator has signed that block, `false`
    ///   otherwise.
    liveness: BitVec,
}

impl LivenessTracker {
    /// Creates a new instance of liveness tracker
    #[inline]
    pub fn new() -> Self {
        Self {
            liveness: BitVec::new(),
        }
    }

    /// Updates liveness tracker with new block data
    pub fn update(&mut self, block_signing_window: usize, block_height: BlockHeight, signed: bool) {
        self.resize(block_signing_window);
        self.liveness
            .set(block_height.value() as usize % block_signing_window, signed);
    }

    /// Checks if validator is live or not
    #[inline]
    // FIXME: use POPCOUNT
    pub fn is_live(&self, missed_block_threshold: usize) -> bool {
        self.liveness.iter().filter(|b| !b).count() < missed_block_threshold
    }

    /// reset tracker to true
    pub fn reset(&mut self) {
        self.liveness.set_all();
    }

    /// grow BitVec to size, no need to shrink.
    fn resize(&mut self, size: usize) {
        if let Some(grow) = size.checked_sub(self.liveness.len()) {
            self.liveness.grow(grow, true);
        }
    }
}

impl Encode for LivenessTracker {
    fn size_hint(&self) -> usize {
        std::mem::size_of::<u16>() + self.liveness.to_bytes().size_hint()
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        (self.liveness.len() as u16).encode_to(dest);
        self.liveness.to_bytes().encode_to(dest);
    }
}

impl Decode for LivenessTracker {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let length = u16::decode(input)?;
        let bytes = <Vec<u8>>::decode(input)?;

        let mut liveness = BitVec::from_bytes(&bytes);
        liveness.truncate(length as usize);

        Ok(LivenessTracker { liveness })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_liveness_tracker_encode_decode() {
        let mut initial = LivenessTracker::new();
        initial.update(10, 1.into(), true);
        initial.update(10, 2.into(), false);

        let encoded = initial.encode();
        let decoded = LivenessTracker::decode(&mut encoded.as_ref()).unwrap();

        assert_eq!(initial, decoded);
    }

    #[test]
    fn check_liveness_tracker() {
        let mut tracker = LivenessTracker::new();
        tracker.update(5, 1.into(), true);
        tracker.update(5, 2.into(), false);
        tracker.update(5, 3.into(), true);
        tracker.update(5, 4.into(), false);
        tracker.update(5, 5.into(), true);

        assert!(tracker.is_live(3));
        assert!(!tracker.is_live(2));
    }
}
