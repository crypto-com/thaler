mod table;
mod tx;

pub use table::{RewardsDistribution, StakingTable};

#[cfg(test)]
mod tests {
    use secp256k1::{
        key::{PublicKey, SecretKey},
        Secp256k1,
    };

    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::init::config::SlashRatio;
    use chain_core::init::params::NetworkParameters;
    use chain_core::state::account::{
        CouncilNode, PunishmentKind, StakedState, StakedStateAddress, UnbondTx, Validator,
    };
    use chain_core::state::tendermint::{BlockHeight, TendermintValidatorPubKey};
    use chain_core::state::validator::NodeJoinRequestTx;
    use chain_storage::buffer::{Get, MemStore, StoreStaking};
    use test_common::chain_env::get_init_network_params;

    use super::*;
    use crate::tx_error::{DepositError, NodeJoinError, PublicTxError, UnbondError, WithdrawError};

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
        staking.validator = Some(Validator::new(CouncilNode::new(
            TendermintValidatorPubKey::Ed25519(seed.clone()),
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
        let amount = Coin::new(10_0000_0000).unwrap();
        table.deposit(&mut store, &addr4, amount).unwrap();
        let node_join = NodeJoinRequestTx {
            nonce: 1,
            address: addr4,
            attributes: Default::default(),
            node_meta: CouncilNode::new(val_pk4.clone()),
        };
        table.node_join(&mut store, 10, &node_join).unwrap();
        assert_eq!(table.end_block(&store, 3), vec![]);

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
        let unbond = UnbondTx {
            from_staked_account: addr4,
            nonce: 3,
            value: Coin::new(2_0000_0000).unwrap(),
            attributes: Default::default(),
        };
        table
            .unbond(&mut store, 10, 0, BlockHeight::genesis(), &unbond)
            .unwrap();
        assert_eq!(
            table.end_block(&store, 3),
            vec![
                (val_pk1, Coin::new(11_0000_0000).unwrap().into()),
                (val_pk4, Coin::zero().into())
            ]
        );
    }

    #[test]
    fn check_jailing() {
        let mut init_params = get_init_network_params(Coin::zero());
        let slash_ratio: SlashRatio = "0.01".parse().unwrap();
        init_params.slashing_config.liveness_slash_percent = slash_ratio;
        init_params.slashing_config.byzantine_slash_percent = slash_ratio;
        let params = NetworkParameters::Genesis(init_params);

        let (mut table, mut store) = init_staking_table();
        let addr1 = staking_address(&[0xcc; 32]);
        let val_pk1 = validator_pubkey(&[0xcc; 32]);
        let evidence = (val_pk1.clone().into(), 1.into(), 0);
        let slashes = table.begin_block(&mut store, &params, 0, 1.into(), &[], &[evidence.clone()]);
        let slash = (
            addr1,
            Coin::new(11_0000_0000).unwrap() * slash_ratio,
            PunishmentKind::ByzantineFault,
        );
        assert_eq!(slashes, vec![slash]);
        let staking = store.get(&addr1).unwrap();
        assert!(staking.is_jailed());
        assert_eq!(
            table.end_block(&store, 3),
            vec![(val_pk1.clone(), Coin::zero().into())]
        );

        // byzantine faults won't slashed again.
        let slashes = table.begin_block(&mut store, &params, 1, 2.into(), &[], &[evidence]);
        assert_eq!(slashes, vec![]);

        // transaction denied after jailed
        let unbond = UnbondTx {
            from_staked_account: addr1,
            nonce: 1,
            value: staking.bonded,
            attributes: Default::default(),
        };
        assert!(matches!(
            table.unbond(&mut store, 10, 2, 3.into(), &unbond),
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
            nonce: 1,
            address: addr1,
            attributes: Default::default(),
            node_meta: CouncilNode::new(val_pk_new),
        };
        assert!(matches!(
            table.node_join(&mut store, 3, &node_join),
            Err(PublicTxError::NodeJoin(NodeJoinError::IsJailed))
        ));
    }

    #[test]
    fn check_used_validator_key() {
        let (mut table, mut store) = init_staking_table();
        let addr1 = staking_address(&[0xcc; 32]);
        let val_pk1 = validator_pubkey(&[0xcc; 32]);
        let val_pk_new = validator_pubkey(&[0xcf; 32]);

        // unbond/deposit/re-join
        let staking = store.get(&addr1).unwrap();
        let unbond = UnbondTx {
            from_staked_account: addr1,
            nonce: 0,
            value: staking.bonded,
            attributes: Default::default(),
        };
        table.unbond(&mut store, 10, 0, 1.into(), &unbond).unwrap();
        assert_eq!(
            table.end_block(&store, 3),
            vec![(val_pk1.clone(), Coin::zero().into())]
        );
        table
            .deposit(&mut store, &addr1, Coin::new(11_0000_0000).unwrap())
            .unwrap();
        let node_join = NodeJoinRequestTx {
            nonce: 2,
            address: addr1,
            attributes: Default::default(),
            node_meta: CouncilNode::new(val_pk_new),
        };
        // change to new validator key
        table.node_join(&mut store, 1, &node_join).unwrap();

        let addr_new = staking_address(&[0xcf; 32]);
        table
            .deposit(&mut store, &addr_new, Coin::new(10_0000_0000).unwrap())
            .unwrap();
        let node_join = NodeJoinRequestTx {
            nonce: 1,
            address: addr_new,
            attributes: Default::default(),
            node_meta: CouncilNode::new(val_pk1),
        };
        // can't join with used key
        assert!(matches!(
            table.node_join(&mut store, 1, &node_join),
            Err(PublicTxError::NodeJoin(
                NodeJoinError::DuplicateValidatorAddress
            ))
        ),);
    }
}
