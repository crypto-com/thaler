use std::collections::BTreeMap;

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use chain_core::state::account::StakedStateAddress;
use chain_core::state::tendermint::TendermintValidatorAddress;

use crate::liveness::LivenessTracker;
use crate::slashing::SlashingSchedule;

/// Runtime state for computing and executing validator punishment
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ValidatorPunishment {
    /// Liveness trackers for staking accounts
    pub validator_liveness: BTreeMap<TendermintValidatorAddress, LivenessTracker>,
    /// Slashing queue for accounts that are scheduled to be slashed
    pub slashing_schedule: BTreeMap<StakedStateAddress, SlashingSchedule>,
}
