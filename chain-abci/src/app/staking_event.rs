use std::fmt;

use serde::ser::{Serialize, SerializeStruct, Serializer};

use abci::Pair as KVPair;
use abci::*;
use chain_core::common::{TendermintEventKey, TendermintEventType, Timespec};
use chain_core::init::coin::Coin;
use chain_core::state::account::{CouncilNodeMeta, PunishmentKind, StakedStateAddress};
use chain_core::tx::fee::Fee;

pub(crate) enum StakingEvent<'a> {
    Deposit(&'a StakedStateAddress, Coin),
    Unbond(&'a StakedStateAddress, Coin, Timespec, Fee),
    Withdraw(&'a StakedStateAddress, Coin),
    NodeJoin(&'a StakedStateAddress, CouncilNodeMeta),
    Reward(&'a StakedStateAddress, Coin),
    Jail(&'a StakedStateAddress, Timespec, PunishmentKind),
    Slash(&'a StakedStateAddress, Coin, Coin, PunishmentKind),
    Unjail(&'a StakedStateAddress),
}

impl<'a> From<StakingEvent<'a>> for Event {
    fn from(event: StakingEvent) -> Self {
        let mut builder = StakingEventBuilder::default();

        match event {
            StakingEvent::Deposit(staking_address, deposit_amount) => {
                builder.deposit(staking_address, deposit_amount)
            }
            StakingEvent::Unbond(staking_address, unbond_amount, unbonded_from, fee) => {
                builder.unbond(staking_address, unbond_amount, unbonded_from, fee)
            }
            StakingEvent::Withdraw(staking_address, withdraw_amount) => {
                builder.withdraw(staking_address, withdraw_amount)
            }
            StakingEvent::NodeJoin(staking_address, council_node) => {
                builder.node_join(staking_address, council_node)
            }
            StakingEvent::Reward(staking_address, reward_amount) => {
                builder.reward(staking_address, reward_amount)
            }
            StakingEvent::Jail(staking_address, timespec, punishment_kind) => {
                builder.jail(staking_address, timespec, punishment_kind)
            }
            StakingEvent::Slash(
                staking_address,
                bonded_slash_amount,
                unbonded_slash_amount,
                punishment_kind,
            ) => builder.slash(
                staking_address,
                bonded_slash_amount,
                unbonded_slash_amount,
                punishment_kind,
            ),
            StakingEvent::Unjail(staking_address) => builder.unjail(staking_address),
        }

        builder.to_event()
    }
}

#[derive(Default)]
struct StakingEventBuilder {
    attributes: Vec<KVPair>,
}

impl StakingEventBuilder {
    fn deposit(&mut self, staking_address: &StakedStateAddress, deposit_amount: Coin) {
        self.attributes
            .push(staking_address_attribute(staking_address));
        self.attributes.push(StakingEventOpType::Deposit.into());

        self.attributes.push(
            StakingDiffField(vec![StakingDiff::Bonded(
                StakingCoinChange::Increase,
                deposit_amount,
            )])
            .into(),
        );
    }

    fn unbond(
        &mut self,
        staking_address: &StakedStateAddress,
        unbond_amount: Coin,
        unbonded_from: Timespec,
        fee: Fee,
    ) {
        self.attributes
            .push(staking_address_attribute(staking_address));
        self.attributes.push(StakingEventOpType::Unbond.into());

        self.attributes.push(
            StakingDiffField(vec![
                StakingDiff::Bonded(
                    StakingCoinChange::Decrease,
                    (unbond_amount + fee.to_coin()).unwrap(),
                ),
                StakingDiff::Unbonded(StakingCoinChange::Increase, unbond_amount),
                StakingDiff::UnbondedFrom(unbonded_from),
            ])
            .into(),
        );
    }

    fn withdraw(&mut self, staking_address: &StakedStateAddress, withdraw_amount: Coin) {
        self.attributes
            .push(staking_address_attribute(staking_address));
        self.attributes.push(StakingEventOpType::Withdraw.into());

        self.attributes.push(
            StakingDiffField(vec![StakingDiff::Unbonded(
                StakingCoinChange::Decrease,
                withdraw_amount,
            )])
            .into(),
        );
    }

    fn node_join(&mut self, staking_address: &StakedStateAddress, node: CouncilNodeMeta) {
        self.attributes
            .push(staking_address_attribute(staking_address));
        self.attributes.push(StakingEventOpType::NodeJoin.into());
        self.attributes
            .push(StakingDiffField(vec![StakingDiff::NodeJoin(node)]).into());
    }

    fn reward(&mut self, staking_address: &StakedStateAddress, reward_amount: Coin) {
        self.attributes
            .push(staking_address_attribute(staking_address));
        self.attributes.push(StakingEventOpType::Reward.into());
        self.attributes.push(
            StakingDiffField(vec![StakingDiff::Bonded(
                StakingCoinChange::Increase,
                reward_amount,
            )])
            .into(),
        );
    }

    fn jail(
        &mut self,
        staking_address: &StakedStateAddress,
        jailed_until: Timespec,
        punishment_kind: PunishmentKind,
    ) {
        self.attributes
            .push(staking_address_attribute(staking_address));
        self.attributes.push(StakingEventOpType::Jail.into());
        self.attributes
            .push(StakingDiffField(vec![StakingDiff::JailedUntil(jailed_until)]).into());

        let mut reason_kv_pair = KVPair::new();
        reason_kv_pair.key = TendermintEventKey::StakingOpReason.into();
        reason_kv_pair.value = punishment_reason(punishment_kind).into_bytes();
        self.attributes.push(reason_kv_pair)
    }

    fn slash(
        &mut self,
        staking_address: &StakedStateAddress,
        bonded_slash_amount: Coin,
        unbonded_slash_amount: Coin,
        punishment_kind: PunishmentKind,
    ) {
        self.attributes
            .push(staking_address_attribute(staking_address));
        self.attributes.push(StakingEventOpType::Slash.into());
        self.attributes.push(
            StakingDiffField(vec![
                StakingDiff::Bonded(StakingCoinChange::Decrease, bonded_slash_amount),
                StakingDiff::Unbonded(StakingCoinChange::Decrease, unbonded_slash_amount),
            ])
            .into(),
        );

        let mut reason_kv_pair = KVPair::new();
        reason_kv_pair.key = TendermintEventKey::StakingOpReason.into();
        reason_kv_pair.value = punishment_reason(punishment_kind).into_bytes();
        self.attributes.push(reason_kv_pair)
    }

    fn unjail(&mut self, staking_address: &StakedStateAddress) {
        self.attributes
            .push(staking_address_attribute(staking_address));
        self.attributes.push(StakingEventOpType::Unjail.into());
    }

    fn to_event(&self) -> Event {
        let mut event = Event::new();
        event.field_type = TendermintEventType::StakingChange.to_string();
        for attribute in self.attributes.iter() {
            event.attributes.push(attribute.clone())
        }

        event
    }
}

#[inline]
fn staking_address_attribute(staking_address: &StakedStateAddress) -> KVPair {
    let mut kv_pair = KVPair::new();
    kv_pair.key = TendermintEventKey::StakingAddress.into();
    kv_pair.value = staking_address.to_string().into_bytes();

    kv_pair
}

#[inline]
fn punishment_reason(punishment_kind: PunishmentKind) -> String {
    match punishment_kind {
        PunishmentKind::ByzantineFault => String::from("ByzantineFault"),
        PunishmentKind::NonLive => String::from("NonLive"),
    }
}

enum StakingEventOpType {
    Deposit,
    Unbond,
    Withdraw,
    NodeJoin,
    Reward,
    Jail,
    Slash,
    Unjail,
}

impl fmt::Display for StakingEventOpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StakingEventOpType::Deposit => write!(f, "deposit"),
            StakingEventOpType::Unbond => write!(f, "unbond"),
            StakingEventOpType::Withdraw => write!(f, "withdraw"),
            StakingEventOpType::NodeJoin => write!(f, "nodejoin"),
            StakingEventOpType::Reward => write!(f, "reward"),
            StakingEventOpType::Jail => write!(f, "jail"),
            StakingEventOpType::Slash => write!(f, "slash"),
            StakingEventOpType::Unjail => write!(f, "unjail"),
        }
    }
}

impl From<StakingEventOpType> for KVPair {
    fn from(op_type: StakingEventOpType) -> Self {
        let mut kv_pair = KVPair::new();

        kv_pair.key = TendermintEventKey::StakingOpType.into();
        kv_pair.value = op_type.to_string().into_bytes();

        kv_pair
    }
}

struct StakingDiffField(Vec<StakingDiff>);

impl From<StakingDiffField> for KVPair {
    fn from(builder: StakingDiffField) -> Self {
        let mut kv_pair = KVPair::new();

        kv_pair.key = TendermintEventKey::StakingDiff.into();
        kv_pair.value = builder.to_string().into_bytes();

        kv_pair
    }
}

impl fmt::Display for StakingDiffField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(&self.0).expect("StakingDiffBuilder serialization error")
        )
    }
}

enum StakingDiff {
    Bonded(StakingCoinChange, Coin),
    Unbonded(StakingCoinChange, Coin),
    UnbondedFrom(Timespec),
    NodeJoin(CouncilNodeMeta),
    JailedUntil(Timespec),
}

impl Serialize for StakingDiff {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            StakingDiff::Bonded(change, coin) => {
                let mut state = serializer.serialize_struct("Bonded", 2)?;
                state.serialize_field("key", "Bonded")?;
                state.serialize_field(
                    "value",
                    format!("{}{}", change, u64::from(coin.to_owned())).as_str(),
                )?;
                state.end()
            }
            StakingDiff::Unbonded(change, coin) => {
                let mut state = serializer.serialize_struct("Unbonded", 2)?;
                state.serialize_field("key", "Unbonded")?;
                state.serialize_field(
                    "value",
                    format!("{}{}", change, u64::from(coin.to_owned())).as_str(),
                )?;
                state.end()
            }
            StakingDiff::UnbondedFrom(unbonded_from) => {
                let mut state = serializer.serialize_struct("UnbondedFrom", 2)?;
                state.serialize_field("key", "UnbondedFrom")?;
                state.serialize_field("value", &unbonded_from)?;
                state.end()
            }
            StakingDiff::NodeJoin(node) => {
                let mut state = serializer.serialize_struct("NodeJoin", 2)?;
                state.serialize_field("key", "CouncilNode")?;
                state.serialize_field("value", node)?;
                state.end()
            }
            StakingDiff::JailedUntil(jailed_until) => {
                let mut state = serializer.serialize_struct("JailedUntil", 2)?;
                state.serialize_field("key", "JailedUntil")?;
                state.serialize_field("value", &jailed_until)?;
                state.end()
            }
        }
    }
}

impl fmt::Display for StakingDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(self).expect("StakingDiff serialization error")
        )
    }
}

enum StakingCoinChange {
    Increase,
    Decrease,
}

impl fmt::Display for StakingCoinChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StakingCoinChange::Increase => write!(f, ""),
            StakingCoinChange::Decrease => write!(f, "-"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_core::state::account::ConfidentialInit;
    use chain_core::state::tendermint::TendermintValidatorPubKey;
    use chain_core::tx::fee::Fee;
    use std::str::FromStr;

    mod staking_diff_field {
        use super::*;

        #[test]
        fn to_string_should_serialize_to_json() {
            let any_amount = Coin::unit();
            let any_staking_diff_1 = StakingDiff::Bonded(StakingCoinChange::Decrease, any_amount);
            let any_staking_diff_2 = StakingDiff::Unbonded(StakingCoinChange::Increase, any_amount);
            let field = StakingDiffField(vec![any_staking_diff_1, any_staking_diff_2]);

            assert_eq!(
                field.to_string(),
                "[{\"key\":\"Bonded\",\"value\":\"-1\"},{\"key\":\"Unbonded\",\"value\":\"1\"}]",
            );
        }
    }

    mod staking_diff {
        use super::*;

        mod bonded {
            use super::*;

            #[test]
            fn to_string_should_serialize_to_json() {
                let any_amount = Coin::unit();
                let staking_diff = StakingDiff::Bonded(StakingCoinChange::Increase, any_amount);

                assert_eq!(
                    staking_diff.to_string(),
                    "{\"key\":\"Bonded\",\"value\":\"1\"}",
                );
            }
        }

        mod unbonded {
            use super::*;

            #[test]
            fn to_string_should_serialize_to_json() {
                let any_amount = Coin::unit();
                let staking_diff = StakingDiff::Unbonded(StakingCoinChange::Increase, any_amount);

                assert_eq!(
                    staking_diff.to_string(),
                    "{\"key\":\"Unbonded\",\"value\":\"1\"}",
                );
            }
        }

        mod unbonded_from {
            use super::*;

            #[test]
            fn to_string_should_serialize_to_json() {
                let any_unbonded_from: Timespec = 1587071014;
                let staking_diff = StakingDiff::UnbondedFrom(any_unbonded_from);

                assert_eq!(
                    staking_diff.to_string(),
                    "{\"key\":\"UnbondedFrom\",\"value\":1587071014}",
                );
            }
        }

        mod node_join {
            use super::*;

            #[test]
            fn to_string_should_serialize_to_json() {
                let any_council_node = any_council_node();
                let staking_diff = StakingDiff::NodeJoin(any_council_node);

                assert_eq!(
                    staking_diff.to_string(),
                    "{\"key\":\"CouncilNode\",\"value\":{\"name\":\"Council Node\",\"security_contact\":\"security@crypto.com\",\"confidential_init\":{\"keypackage\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"},\"consensus_pubkey\":{\"type\":\"tendermint/PubKeyEd25519\",\"value\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}}}",
                );
            }

            fn any_council_node() -> CouncilNodeMeta {
                let any_name = String::from("Council Node");
                let any_security_contact = Some(String::from("security@crypto.com"));
                let any_pub_key = TendermintValidatorPubKey::Ed25519([0u8; 32]);
                let any_cert = ConfidentialInit {
                    keypackage: [0u8; 32].to_vec(),
                };

                CouncilNodeMeta::new_with_details(
                    any_name,
                    any_security_contact,
                    any_pub_key,
                    any_cert,
                )
            }
        }

        mod jailed_until {
            use super::*;

            #[test]
            fn to_string_should_serialize_to_json() {
                let any_jailed_until: Timespec = 1587071014;
                let staking_diff = StakingDiff::JailedUntil(any_jailed_until);

                assert_eq!(
                    staking_diff.to_string(),
                    "{\"key\":\"JailedUntil\",\"value\":1587071014}",
                );
            }
        }
    }

    mod staking_event {
        use super::*;

        mod deposit {
            use super::*;

            #[test]
            fn should_create_deposit_event() {
                let any_staking_address = any_staking_address();
                let any_amount = Coin::unit();

                let event: Event = StakingEvent::Deposit(&any_staking_address, any_amount).into();

                assert_deposit_event(event, any_staking_address, any_amount);
            }
        }

        mod unbond {
            use super::*;

            #[test]
            fn should_create_unbond_event() {
                let any_staking_address = any_staking_address();
                let any_amount = Coin::unit();
                let any_unbonded_from: Timespec = 1587071014;

                let event: Event = StakingEvent::Unbond(
                    &any_staking_address,
                    any_amount,
                    any_unbonded_from,
                    Fee::new(Coin::zero()),
                )
                .into();

                assert_unbonded_event(event, &any_staking_address, any_amount, any_unbonded_from);
            }
        }

        mod withdraw {
            use super::*;

            #[test]
            fn should_create_withdraw_event() {
                let any_staking_address = any_staking_address();
                let any_amount = Coin::unit();

                let event: Event = StakingEvent::Withdraw(&any_staking_address, any_amount).into();

                assert_withdraw_event(event, &any_staking_address, any_amount)
            }
        }

        mod node_join {
            use super::*;
            use chain_core::state::tendermint::TendermintValidatorPubKey;

            #[test]
            fn should_create_node_join_event() {
                let any_staking_address = any_staking_address();
                let any_council_node = any_council_node();

                let event: Event =
                    StakingEvent::NodeJoin(&any_staking_address, any_council_node.clone()).into();

                assert_node_join_event(event, &any_staking_address, any_council_node)
            }

            fn any_council_node() -> CouncilNodeMeta {
                let any_name = String::from("Council Node");
                let any_security_contact = Some(String::from("security@crypto.com"));
                let any_pub_key = TendermintValidatorPubKey::Ed25519([0u8; 32]);
                let any_cert = ConfidentialInit {
                    keypackage: [0u8; 32].to_vec(),
                };

                CouncilNodeMeta::new_with_details(
                    any_name,
                    any_security_contact,
                    any_pub_key,
                    any_cert,
                )
            }
        }

        mod reward {
            use super::*;

            #[test]
            fn should_create_reward_event() {
                let any_staking_address = any_staking_address();
                let any_amount = Coin::unit();

                let event: Event = StakingEvent::Reward(&any_staking_address, any_amount).into();

                assert_reward_event(event, any_staking_address, any_amount);
            }
        }

        mod jail {
            use super::*;

            #[test]
            fn should_create_jail_event() {
                let any_staking_address = any_staking_address();
                let any_time: Timespec = 1587071014;
                let any_jail_reason = PunishmentKind::ByzantineFault;

                let event: Event =
                    StakingEvent::Jail(&any_staking_address, any_time, any_jail_reason).into();

                assert_jail_event(event, any_staking_address, any_time, any_jail_reason);
            }
        }

        mod slash {
            use super::*;

            #[test]
            fn should_create_slash_event() {
                let any_staking_address = any_staking_address();
                let any_bonded_slash_amount = Coin::unit();
                let any_unbonded_slash_amount = Coin::unit();
                let any_jail_reason = PunishmentKind::ByzantineFault;

                let event: Event = StakingEvent::Slash(
                    &any_staking_address,
                    any_bonded_slash_amount,
                    any_unbonded_slash_amount,
                    any_jail_reason,
                )
                .into();

                assert_slash_event(
                    event,
                    any_staking_address,
                    any_bonded_slash_amount,
                    any_unbonded_slash_amount,
                    any_jail_reason,
                );
            }
        }

        mod unjail {
            use super::*;

            #[test]
            fn should_create_unjail_event() {
                let any_staking_address = any_staking_address();

                let event: Event = StakingEvent::Unjail(&any_staking_address).into();

                assert_unjail_event(event, any_staking_address);
            }
        }

        fn assert_deposit_event(
            event: Event,
            staking_address: StakedStateAddress,
            deposit_amount: Coin,
        ) {
            assert_eq!(
                event.field_type,
                TendermintEventType::StakingChange.to_string()
            );
            assert_eq!(event.attributes.len(), 3);

            let staking_address_attribute = event.attributes.first().unwrap();
            assert_kv_pair(
                staking_address_attribute,
                TendermintEventKey::StakingAddress.to_string(),
                staking_address.to_string(),
            );

            let staking_optype_attribute = event.attributes.get(1).unwrap();
            assert_kv_pair(
                staking_optype_attribute,
                TendermintEventKey::StakingOpType.to_string(),
                StakingEventOpType::Deposit.to_string(),
            );

            let staking_diff_attribute = event.attributes.get(2).unwrap();
            let expected_value = format!(
                "[{{\"key\":\"Bonded\",\"value\":\"{}\"}}]",
                u64::from(deposit_amount)
            );
            assert_kv_pair(
                staking_diff_attribute,
                TendermintEventKey::StakingDiff.to_string(),
                expected_value,
            );
        }

        fn assert_unbonded_event(
            event: Event,
            staking_address: &StakedStateAddress,
            unbond_amount: Coin,
            unbonded_from: Timespec,
        ) {
            assert_eq!(
                event.field_type,
                TendermintEventType::StakingChange.to_string()
            );
            assert_eq!(event.attributes.len(), 3);

            let staking_address_attribute = event.attributes.first().unwrap();
            assert_kv_pair(
                staking_address_attribute,
                TendermintEventKey::StakingAddress.to_string(),
                staking_address.to_string(),
            );

            let staking_optype_attribute = event.attributes.get(1).unwrap();
            assert_kv_pair(
                staking_optype_attribute,
                TendermintEventKey::StakingOpType.to_string(),
                StakingEventOpType::Unbond.to_string(),
            );

            let staking_diff_attribute = event.attributes.get(2).unwrap();
            let expected_value = format!(
                "[{{\"key\":\"Bonded\",\"value\":\"-{}\"}},{{\"key\":\"Unbonded\",\"value\":\"{}\"}},{{\"key\":\"UnbondedFrom\",\"value\":{}}}]",
                u64::from(unbond_amount),
                u64::from(unbond_amount),
                unbonded_from,
            );
            assert_kv_pair(
                staking_diff_attribute,
                TendermintEventKey::StakingDiff.to_string(),
                expected_value,
            );
        }

        fn assert_withdraw_event(
            event: Event,
            staking_address: &StakedStateAddress,
            withdraw_amount: Coin,
        ) {
            assert_eq!(
                event.field_type,
                TendermintEventType::StakingChange.to_string()
            );
            assert_eq!(event.attributes.len(), 3);

            let staking_address_attribute = event.attributes.first().unwrap();
            assert_kv_pair(
                staking_address_attribute,
                TendermintEventKey::StakingAddress.to_string(),
                staking_address.to_string(),
            );

            let staking_optype_attribute = event.attributes.get(1).unwrap();
            assert_kv_pair(
                staking_optype_attribute,
                TendermintEventKey::StakingOpType.to_string(),
                StakingEventOpType::Withdraw.to_string(),
            );

            let staking_diff_attribute = event.attributes.get(2).unwrap();
            let expected_value = format!(
                "[{{\"key\":\"Unbonded\",\"value\":\"-{}\"}}]",
                u64::from(withdraw_amount)
            );
            assert_kv_pair(
                staking_diff_attribute,
                TendermintEventKey::StakingDiff.to_string(),
                expected_value,
            );
        }

        fn assert_node_join_event(
            event: Event,
            staking_address: &StakedStateAddress,
            council_node: CouncilNodeMeta,
        ) {
            assert_eq!(
                event.field_type,
                TendermintEventType::StakingChange.to_string()
            );
            assert_eq!(event.attributes.len(), 3);

            let staking_address_attribute = event.attributes.first().unwrap();
            assert_kv_pair(
                staking_address_attribute,
                TendermintEventKey::StakingAddress.to_string(),
                staking_address.to_string(),
            );

            let staking_optype_attribute = event.attributes.get(1).unwrap();
            assert_kv_pair(
                staking_optype_attribute,
                TendermintEventKey::StakingOpType.to_string(),
                StakingEventOpType::NodeJoin.to_string(),
            );

            let staking_diff_attribute = event.attributes.get(2).unwrap();
            let expected_council_node = serde_json::to_string(&council_node)
                .expect("Error when serializing council node info");
            let expected_value = format!(
                "[{{\"key\":\"CouncilNode\",\"value\":{}}}]",
                expected_council_node
            );
            assert_kv_pair(
                staking_diff_attribute,
                TendermintEventKey::StakingDiff.to_string(),
                expected_value,
            );
        }

        fn assert_reward_event(
            event: Event,
            staking_address: StakedStateAddress,
            deposit_amount: Coin,
        ) {
            assert_eq!(
                event.field_type,
                TendermintEventType::StakingChange.to_string()
            );
            assert_eq!(event.attributes.len(), 3);

            let staking_address_attribute = event.attributes.first().unwrap();
            assert_kv_pair(
                staking_address_attribute,
                TendermintEventKey::StakingAddress.to_string(),
                staking_address.to_string(),
            );

            let staking_optype_attribute = event.attributes.get(1).unwrap();
            assert_kv_pair(
                staking_optype_attribute,
                TendermintEventKey::StakingOpType.to_string(),
                StakingEventOpType::Reward.to_string(),
            );

            let staking_diff_attribute = event.attributes.get(2).unwrap();
            let expected_value = format!(
                "[{{\"key\":\"Bonded\",\"value\":\"{}\"}}]",
                u64::from(deposit_amount)
            );
            assert_kv_pair(
                staking_diff_attribute,
                TendermintEventKey::StakingDiff.to_string(),
                expected_value,
            );
        }

        fn assert_jail_event(
            event: Event,
            staking_address: StakedStateAddress,
            timespec: Timespec,
            punishment_kind: PunishmentKind,
        ) {
            assert_eq!(
                event.field_type,
                TendermintEventType::StakingChange.to_string()
            );
            assert_eq!(event.attributes.len(), 4);

            let staking_address_attribute = event.attributes.first().unwrap();
            assert_kv_pair(
                staking_address_attribute,
                TendermintEventKey::StakingAddress.to_string(),
                staking_address.to_string(),
            );

            let staking_optype_attribute = event.attributes.get(1).unwrap();
            assert_kv_pair(
                staking_optype_attribute,
                TendermintEventKey::StakingOpType.to_string(),
                StakingEventOpType::Jail.to_string(),
            );

            let staking_diff_attribute = event.attributes.get(2).unwrap();
            let expected_timespec = timespec.to_string();
            let expected_value = format!(
                "[{{\"key\":\"JailedUntil\",\"value\":{}}}]",
                expected_timespec
            );
            assert_kv_pair(
                staking_diff_attribute,
                TendermintEventKey::StakingDiff.to_string(),
                expected_value,
            );

            let staking_opreason_attribute = event.attributes.get(3).unwrap();
            assert_kv_pair(
                staking_opreason_attribute,
                TendermintEventKey::StakingOpReason.to_string(),
                punishment_reason(punishment_kind),
            );
        }

        fn assert_slash_event(
            event: Event,
            staking_address: StakedStateAddress,
            bonded_slash_amount: Coin,
            unbonded_slash_amount: Coin,
            punishment_kind: PunishmentKind,
        ) {
            assert_eq!(
                event.field_type,
                TendermintEventType::StakingChange.to_string()
            );
            assert_eq!(event.attributes.len(), 4);

            let staking_address_attribute = event.attributes.first().unwrap();
            assert_kv_pair(
                staking_address_attribute,
                TendermintEventKey::StakingAddress.to_string(),
                staking_address.to_string(),
            );

            let staking_optype_attribute = event.attributes.get(1).unwrap();
            assert_kv_pair(
                staking_optype_attribute,
                TendermintEventKey::StakingOpType.to_string(),
                StakingEventOpType::Slash.to_string(),
            );

            let staking_diff_bonded_attribute = event.attributes.get(2).unwrap();
            let expected_value = format!(
                "[{{\"key\":\"Bonded\",\"value\":\"-{}\"}},{{\"key\":\"Unbonded\",\"value\":\"-{}\"}}]",
                u64::from(bonded_slash_amount),
                u64::from(unbonded_slash_amount)
            );
            assert_kv_pair(
                staking_diff_bonded_attribute,
                TendermintEventKey::StakingDiff.to_string(),
                expected_value,
            );

            let staking_opreason_attribute = event.attributes.get(3).unwrap();
            assert_kv_pair(
                staking_opreason_attribute,
                TendermintEventKey::StakingOpReason.to_string(),
                punishment_reason(punishment_kind),
            );
        }

        fn assert_unjail_event(event: Event, staking_address: StakedStateAddress) {
            assert_eq!(
                event.field_type,
                TendermintEventType::StakingChange.to_string()
            );
            assert_eq!(event.attributes.len(), 2);

            let staking_address_attribute = event.attributes.first().unwrap();
            assert_kv_pair(
                staking_address_attribute,
                TendermintEventKey::StakingAddress.to_string(),
                staking_address.to_string(),
            );

            let staking_optype_attribute = event.attributes.get(1).unwrap();
            assert_kv_pair(
                staking_optype_attribute,
                TendermintEventKey::StakingOpType.to_string(),
                StakingEventOpType::Unjail.to_string(),
            );
        }

        fn assert_kv_pair(kv_pair: &KVPair, expected_key: String, expected_value: String) {
            assert_eq!(String::from_utf8_lossy(&kv_pair.key), expected_key);
            assert_eq!(String::from_utf8_lossy(&kv_pair.value), expected_value);
        }
    }

    fn any_staking_address() -> StakedStateAddress {
        StakedStateAddress::from_str("0x83fe11feb0887183eb62c30994bdd9e303497e3d").unwrap()
    }
}
