mod table;
mod tx;

pub use table::{RewardsDistribution, StakingTable};

#[cfg(test)]
mod tests {
    use secp256k1::{
        key::{PublicKey, SecretKey},
        Secp256k1,
    };
    use std::str::FromStr;

    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::init::config::SlashRatio;
    use chain_core::init::params::NetworkParameters;
    use chain_core::state::account::{
        NodeState, PunishmentKind, StakedState, StakedStateAddress, UnbondTx, UnjailTx, Validator,
    };
    use chain_core::state::tendermint::{BlockHeight, TendermintValidatorPubKey};
    use chain_core::state::validator::NodeJoinRequestTx;
    use chain_core::tx::fee::Fee;
    use chain_storage::buffer::{Get, GetStaking, MemStore, StoreStaking};
    use test_common::chain_env::{
        get_init_network_params, mock_council_node, mock_council_node_meta,
    };

    use super::*;
    use crate::app::BeginBlockInfo;
    use crate::staking::table::{PunishmentOutcome, SlashedCoin};
    use crate::tx_error::{
        DepositError, NodeJoinError, PublicTxError, UnbondError, UnjailError, WithdrawError,
    };

    macro_rules! matches {
    ($expression:expr, $( $pattern:pat )|+ $( if $guard: expr )?) => {
        match $expression {
            $( $pattern )|+ $( if $guard )? => true,
            _ => false
        }
    }
}

    type StakingMemStore = MemStore<StakedStateAddress, StakedState>;

    fn staking_address(seed: &[u8; 32]) -> StakedStateAddress {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(seed).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        StakedStateAddress::BasicRedeem(RedeemAddress::from(&public_key))
    }

    fn validator_pubkey(seed: &[u8; 32]) -> TendermintValidatorPubKey {
        TendermintValidatorPubKey::Ed25519(seed.clone())
    }

    fn new_validator(seed: &[u8; 32], bonded: Coin) -> StakedState {
        let mut staking = StakedState::default(staking_address(seed));
        staking.bonded = bonded;
        staking.node_meta = Some(NodeState::CouncilNode(Validator::new(
            mock_council_node_meta(TendermintValidatorPubKey::Ed25519(seed.clone())),
        )));
        staking
    }

    fn init_staking_table() -> (StakingTable, StakingMemStore) {
        let minimal = Coin::new(10_0000_0000).unwrap();
        let genesis_accounts = vec![
            new_validator(
                &[0xcc; 32],
                (minimal + Coin::new(1_0000_0000).unwrap()).unwrap(),
            ),
            new_validator(
                &[0xcd; 32],
                (minimal + Coin::new(2_0000_0000).unwrap()).unwrap(),
            ),
            new_validator(
                &[0xce; 32],
                (minimal + Coin::new(3_0000_0000).unwrap()).unwrap(),
            ),
        ];
        let mut store = StakingMemStore::new();
        for staking in genesis_accounts.iter() {
            #[cfg(debug_assertions)]
            staking.check_invariants(minimal);
            store.set_staking(staking.clone());
        }
        (
            StakingTable::from_genesis(
                &store,
                minimal,
                3,
                &genesis_accounts
                    .iter()
                    .map(|staking| staking.address)
                    .collect::<Vec<_>>(),
            ),
            store,
        )
    }

    #[test]
    fn check_choose_validators() {
        let (mut table, mut store) = init_staking_table();
        let addr4 = staking_address(&[0xcf; 32]);
        let val_pk4 = validator_pubkey(&[0xcf; 32]);
        let nonce = store.get_or_default(&addr4).nonce;

        let amount = Coin::new(10_0000_0000).unwrap();
        table.deposit(&mut store, &addr4, amount).unwrap();

        // deposit doesn't increase nonce
        assert_eq!(store.get(&addr4).unwrap().nonce, nonce);

        let node_join = NodeJoinRequestTx {
            nonce,
            address: addr4,
            attributes: Default::default(),
            node_meta: mock_council_node(val_pk4.clone()),
        };
        table.node_join(&mut store, 10, 0, 0, &node_join).unwrap();
        assert_eq!(table.end_block(&store, 3), vec![]);
        // node-join increase nonce by one
        assert_eq!(store.get(&addr4).unwrap().nonce, nonce + 1);

        // after deposit, replace one of the existing validator
        table
            .deposit(&mut store, &addr4, Coin::new(2_0000_0000).unwrap())
            .unwrap();
        let val_pk1 = validator_pubkey(&[0xcc; 32]);
        assert_eq!(
            table.end_block(&store, 3),
            vec![
                (val_pk4.clone(), Coin::new(12_0000_0000).unwrap().into()),
                (val_pk1.clone(), Coin::zero().into())
            ]
        );

        // after unbond, the previous validator recover
        let nonce = store.get(&addr4).unwrap().nonce;
        let unbond = UnbondTx {
            from_staked_account: addr4,
            nonce,
            value: Coin::new(2_0000_0000).unwrap(),
            attributes: Default::default(),
        };
        table
            .unbond(
                &mut store,
                10,
                0,
                BlockHeight::genesis(),
                &unbond,
                Fee::zero(),
            )
            .unwrap();
        assert_eq!(
            table.end_block(&store, 3),
            vec![
                (val_pk1, Coin::new(11_0000_0000).unwrap().into()),
                (val_pk4, Coin::zero().into())
            ]
        );
        // unbond increase nonce by one
        assert_eq!(store.get(&addr4).unwrap().nonce, nonce + 1);

        // test withdraw transaction
        table
            .withdraw(&mut store, 10 + 10, &addr4, Coin::new(2_0000_0000).unwrap())
            .unwrap();
        // withdraw increase nonce by one
        assert_eq!(store.get(&addr4).unwrap().nonce, nonce + 2);
    }

    #[test]
    fn check_jailing() {
        let mut init_params = get_init_network_params(Coin::zero());
        let slash_ratio: SlashRatio = "0.01".parse().unwrap();
        init_params.slashing_config.liveness_slash_percent = slash_ratio;
        init_params.slashing_config.byzantine_slash_percent = slash_ratio;
        let params = NetworkParameters::Genesis(init_params);
        let info = BeginBlockInfo {
            params: &params,
            max_evidence_age: 10,
            block_time: 0,
            block_height: 0.into(),
            voters: &[],
            evidences: &[],
        };

        let (mut table, mut store) = init_staking_table();
        let addr1 = staking_address(&[0xcc; 32]);
        let val_pk1 = validator_pubkey(&[0xcc; 32]);
        let evidence = (val_pk1.clone().into(), 1.into(), 0);
        let block_time: u64 = 0;
        let punishment_outcomes = table.begin_block(
            &mut store,
            &BeginBlockInfo {
                block_time,
                block_height: 1.into(),
                evidences: &[evidence.clone()],
                ..info
            },
        );

        let bonded_slashed = Coin::new(11_0000_0000).unwrap() * slash_ratio;
        let unbonded_slashed = Coin::zero();
        let punishment_outcome = PunishmentOutcome {
            staking_address: addr1,
            slashed_coin: SlashedCoin {
                bonded: bonded_slashed,
                unbonded: unbonded_slashed,
            },
            punishment_kind: PunishmentKind::ByzantineFault,
            jailed_until: Some(block_time.saturating_add(info.get_unbonding_period())),
        };
        assert_eq!(punishment_outcomes, vec![punishment_outcome]);
        let staking = store.get(&addr1).unwrap();
        assert!(staking.is_jailed());
        assert_eq!(
            table.end_block(&store, 3),
            vec![(val_pk1.clone(), Coin::zero().into())]
        );

        let nonce = store.get(&addr1).unwrap().nonce;
        // slashing/jailing don't increase nonce
        assert_eq!(nonce, 0);

        // byzantine faults won't slashed again.
        let punishment_outcomes = table.begin_block(
            &mut store,
            &BeginBlockInfo {
                block_time: 1,
                block_height: 2.into(),
                evidences: &[evidence],
                ..info
            },
        );
        assert_eq!(punishment_outcomes, vec![]);

        // transaction denied after jailed
        let unbond = UnbondTx {
            from_staked_account: addr1,
            nonce,
            value: staking.bonded,
            attributes: Default::default(),
        };
        assert!(matches!(
            table.unbond(&mut store, 10, 2, 3.into(), &unbond, Fee::zero()),
            Err(PublicTxError::Unbond(UnbondError::IsJailed))
        ));
        assert!(matches!(
            table.deposit(&mut store, &addr1, Coin::new(2_0000_0000).unwrap()),
            Err(DepositError::IsJailed)
        ));
        assert!(matches!(
            table.withdraw(&mut store, 0, &addr1, staking.unbonded),
            Err(WithdrawError::IsJailed)
        ));
        let val_pk_new = validator_pubkey(&[0xcf; 32]);
        let node_join = NodeJoinRequestTx {
            nonce,
            address: addr1,
            attributes: Default::default(),
            node_meta: mock_council_node(val_pk_new),
        };
        assert!(matches!(
            table.node_join(&mut store, 3, 0, 0, &node_join),
            Err(PublicTxError::NodeJoin(NodeJoinError::IsJailed))
        ));
        // failed execution don't increase nonce
        assert_eq!(store.get(&addr1).unwrap().nonce, nonce);

        // unjail
        let tx = UnjailTx {
            nonce,
            address: addr1,
            attributes: Default::default(),
        };
        assert!(matches!(
            table.unjail(&mut store, 1 + 1, &tx),
            Err(PublicTxError::Unjail(UnjailError::JailTimeNotExpired))
        ));
        table.unjail(&mut store, 1 + 10, &tx).unwrap();
        // unjail increase nonce by one
        let staking = store.get(&addr1).unwrap();
        assert_eq!(staking.nonce, nonce + 1);
        assert!(!staking.is_jailed());
    }

    fn unbond_deposit_rejoin(
        table: &mut StakingTable,
        store: &mut impl StoreStaking,
        addr: StakedStateAddress,
        amount: Coin,
        val_pk_new: TendermintValidatorPubKey,
    ) -> Result<(), PublicTxError> {
        // unbond/deposit/re-join
        let staking = store.get(&addr).unwrap();
        let val_pk = match &staking.node_meta {
            Some(NodeState::CouncilNode(v)) => &v.council_node.consensus_pubkey,
            _ => unreachable!(),
        };
        let unbond = UnbondTx {
            from_staked_account: addr,
            nonce: staking.nonce,
            value: amount,
            attributes: Default::default(),
        };
        table
            .unbond(store, 10, 0, 1.into(), &unbond, Fee::zero())
            .unwrap();
        assert_eq!(
            table.end_block(&*store, 3),
            vec![(val_pk.clone(), Coin::zero().into())]
        );
        table.deposit(store, &addr, amount).unwrap();
        let node_join = NodeJoinRequestTx {
            nonce: staking.nonce + 1,
            address: addr,
            attributes: Default::default(),
            node_meta: mock_council_node(val_pk_new.clone()),
        };
        // change to new validator key
        let result = table.node_join(store, 1, 1, 0, &node_join);
        if result.is_ok() {
            let staking = store.get(&addr).unwrap();
            assert_eq!(
                table.end_block(&*store, 3),
                vec![(val_pk_new, staking.bonded.into())]
            );
        }
        result.map(|_| ())
    }

    #[test]
    fn check_used_validator_key() {
        let (mut table, mut store) = init_staking_table();
        let addr1 = staking_address(&[0xcc; 32]);
        let val_pk1 = validator_pubkey(&[0xcc; 32]);

        for i in 0..10 {
            let val_pk_new = validator_pubkey(&[0x00 + i; 32]);
            unbond_deposit_rejoin(
                &mut table,
                &mut store,
                addr1,
                Coin::new(11_0000_0000).unwrap(),
                val_pk_new,
            )
            .unwrap();
        }

        // exceed max used validator address
        let val_pk_new = validator_pubkey(&[0x00 + 10; 32]);
        assert!(matches!(
            unbond_deposit_rejoin(
                &mut table,
                &mut store,
                addr1,
                Coin::new(11_0000_0000).unwrap(),
                val_pk_new,
            ),
            Err(PublicTxError::NodeJoin(
                NodeJoinError::UsedValidatorAddrFull
            ))
        ));

        let addr_new = staking_address(&[0xcf; 32]);
        table
            .deposit(&mut store, &addr_new, Coin::new(10_0000_0000).unwrap())
            .unwrap();
        let node_join = NodeJoinRequestTx {
            nonce: 0,
            address: addr_new,
            attributes: Default::default(),
            node_meta: mock_council_node(val_pk1),
        };
        // can't join with used key
        assert!(matches!(
            table.node_join(&mut store, 1, 0, 0, &node_join),
            Err(PublicTxError::NodeJoin(
                NodeJoinError::DuplicateValidatorAddress
            ))
        ));
    }

    #[test]
    fn check_nonlive_fault() {
        let (mut table, mut store) = init_staking_table();
        let addr1 = staking_address(&[0xcc; 32]);
        let val_pk1 = validator_pubkey(&[0xcc; 32]);

        let mut init_params = get_init_network_params(Coin::zero());
        init_params.jailing_config.block_signing_window = 5;
        init_params.jailing_config.missed_block_threshold = 4;
        let params = NetworkParameters::Genesis(init_params);
        let info = BeginBlockInfo {
            params: &params,
            max_evidence_age: 61,
            block_time: 0,
            block_height: 0.into(),
            voters: &[],
            evidences: &[],
        };

        for i in 1..=3 {
            let punishment_outcomes = table.begin_block(
                &mut store,
                &BeginBlockInfo {
                    block_time: 1 + i,
                    block_height: i.into(),
                    voters: &[(val_pk1.clone().into(), false)],
                    ..info
                },
            );
            assert_eq!(punishment_outcomes, vec![]);
        }
        // non-live fault
        let punishment_outcomes = table.begin_block(
            &mut store,
            &BeginBlockInfo {
                block_time: 1,
                block_height: 5.into(),
                voters: &[(val_pk1.clone().into(), false)],
                ..info
            },
        );
        assert_eq!(punishment_outcomes[0].staking_address, addr1);
        assert_eq!(
            punishment_outcomes[0].punishment_kind,
            PunishmentKind::NonLive
        );
        assert_eq!(
            punishment_outcomes[0].jailed_until, None,
            "NonLive should not jail"
        );
    }

    /// Tests:
    /// - liveness tracking not interrupted when temporarily not selected
    /// - liveness tracking not interrupted when temporarily unbonded and re-joined again
    #[test]
    fn check_liveness_tracking() {
        // check liveness tracking not interuppted by temporarily inactive.
        let (mut table, mut store) = init_staking_table();
        let addr1 = staking_address(&[0xcc; 32]);
        let val_pk1 = validator_pubkey(&[0xcc; 32]);

        let node_join_tx = |nonce: u64| NodeJoinRequestTx {
            nonce,
            address: addr1,
            attributes: Default::default(),
            node_meta: mock_council_node(val_pk1.clone()),
        };

        let mut init_params = get_init_network_params(Coin::zero());
        init_params.jailing_config.block_signing_window = 50;
        init_params.jailing_config.missed_block_threshold = 5;
        let params = NetworkParameters::Genesis(init_params);
        let info = BeginBlockInfo {
            params: &params,
            max_evidence_age: 61,
            block_time: 0,
            block_height: 0.into(),
            voters: &[],
            evidences: &[],
        };

        // miss two blocks
        for i in 1..=2 {
            let punishment_outcomes = table.begin_block(
                &mut store,
                &BeginBlockInfo {
                    block_time: 1 + i,
                    block_height: i.into(),
                    voters: &[(val_pk1.clone().into(), false)],
                    ..info
                },
            );
            assert_eq!(punishment_outcomes, vec![]);
        }

        // validator1 not selected
        assert_eq!(
            table.end_block(&mut store, 2),
            vec![(val_pk1.clone(), Coin::zero().into())]
        );

        for i in 3..=4 {
            let punishment_outcomes = table.begin_block(
                &mut store,
                &BeginBlockInfo {
                    block_time: 1 + i,
                    block_height: i.into(),
                    ..info
                },
            );
            assert_eq!(punishment_outcomes, vec![]);
        }

        // validator1 selected again
        assert_eq!(
            table.end_block(&mut store, 3),
            vec![(val_pk1.clone(), Coin::new(11_0000_0000).unwrap().into())]
        );

        for i in 5..=6 {
            let punishment_outcomes = table.begin_block(
                &mut store,
                &BeginBlockInfo {
                    block_time: 1 + i,
                    block_height: i.into(),
                    voters: &[(val_pk1.clone().into(), false)],
                    ..info
                },
            );
            assert_eq!(punishment_outcomes, vec![]);
        }

        // non-live fault
        let punishment_outcomes = table.begin_block(
            &mut store,
            &BeginBlockInfo {
                block_time: 8,
                block_height: 7.into(),
                voters: &[(val_pk1.clone().into(), false)],
                ..info
            },
        );
        assert_eq!(punishment_outcomes[0].staking_address, addr1);
        assert_eq!(
            punishment_outcomes[0].punishment_kind,
            PunishmentKind::NonLive
        );
        assert_eq!(
            punishment_outcomes[0].jailed_until, None,
            "NonLive should not jail"
        );
        let bonded_slashed = punishment_outcomes[0].slashed_coin.bonded;
        let unbonded_slashed = punishment_outcomes[0].slashed_coin.unbonded;
        assert_eq!(
            bonded_slashed,
            Coin::new(11_0000_0000).unwrap() * SlashRatio::from_str("0.1").unwrap()
        );
        assert_eq!(unbonded_slashed, Coin::zero(),);
        assert_eq!(
            table.end_block(&mut store, 3),
            vec![(val_pk1.clone(), Coin::zero().into())]
        );

        // re-join
        let slashed = (bonded_slashed + unbonded_slashed).unwrap();
        table.deposit(&mut store, &addr1, slashed).unwrap();
        table
            .node_join(&mut store, 8, 0, 0, &node_join_tx(0))
            .unwrap();
        assert_eq!(
            table.end_block(&mut store, 3),
            vec![(val_pk1.clone(), Coin::new(11_0000_0000).unwrap().into())]
        );

        // miss two blocks
        for i in 8..=9 {
            let punishment_outcomes = table.begin_block(
                &mut store,
                &BeginBlockInfo {
                    block_time: 1 + i,
                    block_height: i.into(),
                    voters: &[(val_pk1.clone().into(), false)],
                    ..info
                },
            );
            assert_eq!(punishment_outcomes, vec![]);
        }

        let unbond = UnbondTx {
            from_staked_account: addr1,
            nonce: 1,
            value: Coin::new(11_0000_0000).unwrap(),
            attributes: Default::default(),
        };
        table
            .unbond(&mut store, 10, 10, 9.into(), &unbond, Fee::zero())
            .unwrap();

        assert_eq!(
            table.end_block(&mut store, 3),
            vec![(val_pk1.clone(), Coin::zero().into())]
        );

        for i in 10..=11 {
            let punishment_outcomes = table.begin_block(
                &mut store,
                &BeginBlockInfo {
                    block_time: 1 + i,
                    block_height: i.into(),
                    ..info
                },
            );
            assert_eq!(punishment_outcomes, vec![]);
        }

        table
            .deposit(&mut store, &addr1, Coin::new(11_0000_0000).unwrap())
            .unwrap();
        table
            .node_join(&mut store, 11, 0, 0, &node_join_tx(2))
            .unwrap();
        assert_eq!(
            table.end_block(&mut store, 3),
            vec![(val_pk1.clone(), Coin::new(11_0000_0000).unwrap().into())]
        );

        for i in 12..=13 {
            let punishment_outcomes = table.begin_block(
                &mut store,
                &BeginBlockInfo {
                    block_time: 1 + i,
                    block_height: i.into(),
                    voters: &[(val_pk1.clone().into(), false)],
                    ..info
                },
            );
            assert_eq!(punishment_outcomes, vec![]);
        }

        // non-live fault again
        let punishment_outcomes = table.begin_block(
            &mut store,
            &BeginBlockInfo {
                block_time: 15,
                block_height: 14.into(),
                voters: &[(val_pk1.clone().into(), false)],
                ..info
            },
        );
        assert_eq!(punishment_outcomes[0].staking_address, addr1);
        assert_eq!(
            punishment_outcomes[0].punishment_kind,
            PunishmentKind::NonLive
        );
        assert_eq!(
            punishment_outcomes[0].jailed_until, None,
            "NonLive should not jail"
        );

        assert_eq!(
            table.end_block(&mut store, 3),
            vec![(val_pk1.clone(), Coin::zero().into())]
        );
    }

    /// Tests:
    /// - byzantine fault detected after unbonded.
    /// - byzantine fault detected after validator key changed.
    #[test]
    fn check_byzantine() {
        let (mut table, mut store) = init_staking_table();
        let bonded = Coin::new(11_0000_0000).unwrap();

        let mut init_params = get_init_network_params(Coin::zero());
        init_params.slashing_config.liveness_slash_percent = "0.1".parse().unwrap();
        let slash_percent = "0.1";
        init_params.slashing_config.byzantine_slash_percent = slash_percent.parse().unwrap();
        let params = NetworkParameters::Genesis(init_params);
        let info = BeginBlockInfo {
            params: &params,
            block_time: 0,
            block_height: 0.into(),
            max_evidence_age: 10,
            voters: &[],
            evidences: &[],
        };

        let addr1 = staking_address(&[0xcc; 32]);
        let val_pk1 = validator_pubkey(&[0xcc; 32]);

        let unbond_amount = Coin::new(11_0000_0000).unwrap();
        let unbond = UnbondTx {
            from_staked_account: addr1,
            nonce: 0,
            value: unbond_amount,
            attributes: Default::default(),
        };
        table
            .unbond(&mut store, 10, 1, 1.into(), &unbond, Fee::zero())
            .unwrap();
        assert_eq!(store.get(&addr1).unwrap().unbonded, unbond_amount);
        let bonded = (bonded - unbond_amount).unwrap();

        assert_eq!(
            table.end_block(&mut store, 3),
            vec![(val_pk1.clone(), Coin::zero().into())]
        );

        let block_time = 2;
        let punishment_outcomes = table.begin_block(
            &mut store,
            &BeginBlockInfo {
                block_time,
                block_height: 2.into(),
                evidences: &[(val_pk1.clone().into(), 1.into(), 1)],
                ..info
            },
        );
        let slash_ratio = SlashRatio::from_str(slash_percent).unwrap();
        let bonded_slashed = bonded * slash_ratio;
        let unbonded_slashed = unbond_amount * slash_ratio;
        let expected_jailed_until = block_time.saturating_add(info.get_unbonding_period());
        assert_eq!(
            punishment_outcomes,
            vec![PunishmentOutcome {
                staking_address: addr1,
                slashed_coin: SlashedCoin {
                    bonded: bonded_slashed,
                    unbonded: unbonded_slashed,
                },
                punishment_kind: PunishmentKind::ByzantineFault,
                jailed_until: Some(expected_jailed_until),
            }]
        );
        let staking = store.get(&addr1).unwrap();
        assert_eq!(staking.unbonded, Coin::new(9_9000_0000).unwrap());
        assert!(staking.is_jailed());

        let addr2 = staking_address(&[0xcd; 32]);
        let val_pk2 = validator_pubkey(&[0xcd; 32]);
        let val_pk_new = validator_pubkey(&[0x00; 32]);

        let unbond = UnbondTx {
            from_staked_account: addr2,
            nonce: 0,
            value: Coin::new(12_0000_0000).unwrap(),
            attributes: Default::default(),
        };
        table
            .unbond(&mut store, 10, 2, 2.into(), &unbond, Fee::zero())
            .unwrap();
        assert_eq!(
            table.end_block(&mut store, 3),
            vec![(val_pk2.clone(), Coin::zero().into())]
        );

        // re-join with new pk
        table
            .deposit(&mut store, &addr2, Coin::new(12_0000_0000).unwrap())
            .unwrap();
        let tx = NodeJoinRequestTx {
            nonce: 1,
            address: addr2,
            attributes: Default::default(),
            node_meta: mock_council_node(val_pk_new.clone()),
        };
        table.node_join(&mut store, 2, 0, 0, &tx).unwrap();
        assert_eq!(
            table.end_block(&mut store, 3),
            vec![(val_pk_new.clone(), Coin::new(12_0000_0000).unwrap().into())]
        );

        let staking = store.get(&addr2).unwrap();
        let slash_ratio = SlashRatio::from_str("0.1").unwrap();
        let bonded_slashed = staking.bonded * slash_ratio;
        let unbonded_slashed = staking.unbonded * slash_ratio;

        // byzantine evidence of old key
        let block_time = 3;
        let punishment_outcomes = table.begin_block(
            &mut store,
            &BeginBlockInfo {
                block_time,
                block_height: 3.into(),
                evidences: &[(val_pk2.clone().into(), 2.into(), 2)],
                ..info
            },
        );
        let expected_jailed_until = block_time + info.get_unbonding_period();
        assert_eq!(
            punishment_outcomes,
            vec![PunishmentOutcome {
                staking_address: addr2,
                slashed_coin: SlashedCoin {
                    bonded: bonded_slashed,
                    unbonded: unbonded_slashed,
                },
                punishment_kind: PunishmentKind::ByzantineFault,
                jailed_until: Some(expected_jailed_until),
            }]
        );
        let staking = store.get(&addr2).unwrap();
        assert_eq!(
            staking.bonded,
            Coin::new(12_0000_0000 - 1_2000_0000).unwrap()
        );
        assert!(staking.is_jailed());
    }
}
