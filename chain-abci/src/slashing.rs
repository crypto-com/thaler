use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use chain_core::common::Timespec;
use chain_core::init::config::SlashRatio;
use chain_core::state::account::PunishmentKind;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
/// Slashing schedule for a staking account
pub struct SlashingSchedule {
    /// Slash ratio for an account
    pub slash_ratio: SlashRatio,
    /// Time after which slashing can be performed
    pub slashing_time: Timespec,
    /// Kind of punishment for which the account is scheduled to be slashed
    pub punishment_kind: PunishmentKind,
}

impl SlashingSchedule {
    /// Creates a new instance of `SlashingSchedule`
    #[inline]
    pub fn new(
        slash_ratio: SlashRatio,
        slashing_time: Timespec,
        punishment_kind: PunishmentKind,
    ) -> Self {
        Self {
            slash_ratio,
            slashing_time,
            punishment_kind,
        }
    }

    /// Updates slash ratio (only if proposed ratio is greater than current)
    #[inline]
    pub fn update_slash_ratio(&mut self, new_ratio: SlashRatio, punishment_kind: PunishmentKind) {
        if new_ratio > self.slash_ratio {
            self.slash_ratio = new_ratio;
            self.punishment_kind = punishment_kind;
        }
    }

    /// Returns true if account can be slashed at a given time
    #[inline]
    pub fn can_slash(&self, current_time: Timespec) -> bool {
        current_time >= self.slashing_time
    }
}
