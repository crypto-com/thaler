use chain_core::state::account::StakedStateAddress;
use chain_core::state::tendermint::TendermintVotePower;
use chain_tx_validation::Error;

use crate::app::{update_account, ChainNodeApp};
use crate::enclave_bridge::EnclaveProxy;
use crate::storage::tx::get_account;

impl<T: EnclaveProxy> ChainNodeApp<T> {
    /// Jails staking account with given address
    pub fn jail_account(&mut self, staking_address: StakedStateAddress) -> Result<(), Error> {
        let mut account = get_account(
            &staking_address,
            &self.uncommitted_account_root_hash,
            &self.accounts,
        )?;

        if account.is_jailed() {
            // Return early if account is already jailed
            return Ok(());
        }

        let last_state = self
            .last_state
            .as_ref()
            .expect("Last state not found. Init chain was not called.");

        let block_time = last_state.block_time;
        let jail_duration: i64 = last_state.jailing_config.jail_duration.into();

        account.jail_until(block_time + jail_duration);

        let (new_root, _) = update_account(
            account,
            &self.uncommitted_account_root_hash,
            &mut self.accounts,
        );
        self.uncommitted_account_root_hash = new_root;
        self.power_changed_in_block
            .insert(staking_address, TendermintVotePower::zero());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::str::FromStr;
    use std::sync::Arc;

    use abci::{Application, PubKey, RequestInitChain};
    use kvdb_memorydb::create;
    use protobuf::well_known_types::Timestamp;
    use secp256k1::{key::PublicKey, key::SecretKey, Secp256k1};

    use chain_core::common::MerkleTree;
    use chain_core::compute_app_hash;
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::init::config::{
        AccountType, InitConfig, InitNetworkParameters, InitialValidator, JailingParameters,
        SlashRatio, SlashingParameters, ValidatorKeyType,
    };
    use chain_core::tx::fee::{LinearFee, Milli};

    use crate::enclave_bridge::mock::MockClient;
    use crate::storage::account::{AccountStorage, AccountWrapper};
    use crate::storage::tx::StarlingFixedKey;
    use crate::storage::{Storage, NUM_COLUMNS};

    const TEST_CHAIN_ID: &str = "test-00";

    #[test]
    fn check_successful_jailing() {
        let storage = Storage::new_db(Arc::new(create(NUM_COLUMNS.unwrap())));
        let mut account_storage =
            AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20).expect("account db");

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let address = RedeemAddress::from(&public_key);
        let staking_account_address = StakedStateAddress::BasicRedeem(address);

        let mut validator_pubkey = PubKey::new();
        validator_pubkey.field_type = "Ed25519".to_string();
        validator_pubkey.data =
            base64::decode("EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=").unwrap();

        let mut validator_voting_power = BTreeMap::new();
        validator_voting_power.insert(staking_account_address, TendermintVotePower::zero());

        let mut distribution = BTreeMap::new();
        distribution.insert(address, (Coin::max(), AccountType::ExternallyOwnedAccount));
        distribution.insert(
            RedeemAddress::default(),
            (Coin::zero(), AccountType::Contract),
        );

        let init_network_params = InitNetworkParameters {
            initial_fee_policy: LinearFee::new(Milli::new(0, 0), Milli::new(0, 0)),
            required_council_node_stake: Coin::max(),
            unbonding_period: 1,
            jailing_config: JailingParameters {
                jail_duration: 60,
                block_signing_window: 5,
                missed_block_threshold: 1,
            },
            slashing_config: SlashingParameters {
                liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
                byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
                slash_wait_period: 10800,
            },
        };

        let init_config = InitConfig::new(
            distribution,
            RedeemAddress::default(),
            RedeemAddress::default(),
            RedeemAddress::default(),
            init_network_params,
            vec![InitialValidator {
                staking_account_address: address,
                consensus_pubkey_type: ValidatorKeyType::Ed25519,
                consensus_pubkey_b64: "EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=".to_string(),
            }],
        );

        let timestamp = Timestamp::new();

        let (accounts, rewards_pool_state, _) = init_config
            .validate_config_get_genesis(timestamp.get_seconds())
            .expect("Error while validating distribution");

        let mut keys: Vec<StarlingFixedKey> =
            accounts.iter().map(|account| account.key()).collect();
        let mut wrapped: Vec<AccountWrapper> = accounts
            .iter()
            .map(|account| AccountWrapper(account.clone()))
            .collect();

        let new_account_root = account_storage
            .insert(None, &mut keys, &mut wrapped)
            .expect("initial insert");

        let transaction_tree = MerkleTree::empty();

        let genesis_app_hash =
            compute_app_hash(&transaction_tree, &new_account_root, &rewards_pool_state);

        let mut app = ChainNodeApp::new_with_storage(
            MockClient::new(0),
            &hex::encode_upper(genesis_app_hash),
            TEST_CHAIN_ID,
            storage,
            account_storage,
        );

        // Init Chain

        let mut request_init_chain = RequestInitChain::default();
        request_init_chain.set_time(timestamp);
        request_init_chain.set_app_state_bytes(serde_json::to_vec(&init_config).unwrap());
        request_init_chain.set_chain_id(String::from(TEST_CHAIN_ID));
        let response_init_chain = app.init_chain(&request_init_chain);

        let validators = response_init_chain.validators.to_vec();

        assert_eq!(1, validators.len());
        assert_eq!(
            100000000000,
            i64::from(
                *app.validator_voting_power
                    .get(&staking_account_address)
                    .unwrap()
            )
        );

        // Check jailing

        app.jail_account(staking_account_address)
            .expect("Unable to jail account");

        let account = get_account(
            &staking_account_address,
            &app.uncommitted_account_root_hash,
            &app.accounts,
        )
        .unwrap();

        assert!(account.is_jailed());
        assert_eq!(
            TendermintVotePower::zero(),
            *app.power_changed_in_block
                .get(&staking_account_address)
                .unwrap()
        );
    }
}
