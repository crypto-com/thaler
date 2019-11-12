mod abci_app;

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use abci::*;
use kvdb_memorydb::create;
use parity_scale_codec::Encode;
use protobuf::well_known_types::Timestamp;
use secp256k1::{
    key::{PublicKey, SecretKey},
    Secp256k1,
};

use abci_app::{get_account, get_ecdsa_witness, get_enclave_bridge_mock};
use chain_abci::app::ChainNodeApp;
use chain_abci::enclave_bridge::mock::MockClient;
use chain_abci::storage::account::{AccountStorage, AccountWrapper};
use chain_abci::storage::tx::StarlingFixedKey;
use chain_abci::storage::*;
use chain_core::common::{MerkleTree, H256};
use chain_core::compute_app_hash;
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::init::config::{
    InitConfig, InitNetworkParameters, JailingParameters, NetworkParameters, SlashRatio,
    SlashingParameters, ValidatorKeyType, ValidatorPubkey,
};
use chain_core::state::account::{
    CouncilNode, PunishmentKind, StakedStateAddress, StakedStateDestination,
    StakedStateOpAttributes, StakedStateOpWitness, UnbondTx, ValidatorName,
    ValidatorSecurityContact,
};
use chain_core::state::tendermint::{TendermintValidatorAddress, TendermintVotePower};
use chain_core::tx::fee::{LinearFee, Milli};
use chain_core::tx::{TransactionId, TxAux};

const TEST_CHAIN_ID: &str = "test-00";

/// Need to add more seed and validator public keys, if need more validator nodes.
const SEEDS: [[u8; 32]; 2] = [[0xcd; 32], [0xab; 32]];
const VALIDATOR_PUB_KEYS: [&str; 2] = [
    "EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=",
    "Vcrw/tEI0JOXw2SZGeowDxw5+Eot8qndCJoh2m6RC/M=",
];

fn create_storage() -> (Storage, AccountStorage) {
    (
        Storage::new_db(Arc::new(create(NUM_COLUMNS.unwrap()))),
        AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20)
            .expect("Unable to create account storage"),
    )
}

fn get_init_network_params(share: Coin) -> InitNetworkParameters {
    InitNetworkParameters {
        initial_fee_policy: LinearFee::new(Milli::new(0, 0), Milli::new(0, 0)),
        required_council_node_stake: share,
        unbonding_period: 1,
        jailing_config: JailingParameters {
            jail_duration: 60,
            block_signing_window: 5,
            missed_block_threshold: 1,
        },
        slashing_config: SlashingParameters {
            liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
            byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
            slash_wait_period: 5,
        },
        max_validators: 1,
    }
}

fn get_nodes(
    addresses: &[Account],
) -> BTreeMap<RedeemAddress, (ValidatorName, ValidatorSecurityContact, ValidatorPubkey)> {
    let mut nodes = BTreeMap::new();

    for acct in addresses {
        let node_pubkey = (
            acct.name.clone(),
            None,
            ValidatorPubkey {
                consensus_pubkey_type: ValidatorKeyType::Ed25519,
                consensus_pubkey_b64: acct.validator_pub_key.clone(),
            },
        );
        nodes.insert(acct.address, node_pubkey);
    }

    nodes
}

struct Account {
    secret_key: SecretKey,
    address: RedeemAddress,
    staking_address: StakedStateAddress,
    validator_pub_key: String,
    name: String,
}

impl Account {
    fn new(seed: &[u8; 32], validator_pub_key: String, name: String) -> Account {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(seed).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let address = RedeemAddress::from(&public_key);
        let staking_address = StakedStateAddress::BasicRedeem(address);

        Account {
            secret_key,
            address,
            staking_address,
            validator_pub_key,
            name,
        }
    }
}

struct TestEnv {
    dist_coin: Coin,
    rewards_pool: Coin,

    genesis_app_hash: H256,
    timestamp: Timestamp,
    init_config: InitConfig,
    council_nodes: Vec<(StakedStateAddress, CouncilNode)>,

    accounts: Vec<Account>,
}

impl TestEnv {
    fn new(
        dist_coin: Coin,
        rewards_pool: Coin,
        count: usize,
    ) -> (TestEnv, Storage, AccountStorage) {
        let (storage, mut account_storage) = create_storage();
        let accounts: Vec<Account> = (0..count)
            .map(|i| {
                Account::new(
                    &SEEDS[i],
                    VALIDATOR_PUB_KEYS[i].to_owned(),
                    format!("test {}", i),
                )
            })
            .collect();

        let share = Coin::new(u64::from(dist_coin) / accounts.len() as u64).unwrap();
        let init_network_params = get_init_network_params(share);

        let mut distribution = BTreeMap::new();
        for acct in &accounts {
            distribution.insert(acct.address, (StakedStateDestination::Bonded, share));
        }

        let init_config = InitConfig::new(
            rewards_pool,
            distribution,
            init_network_params.clone(),
            get_nodes(&accounts),
        );

        let timestamp = Timestamp::new();
        let (states, rewards_pool_state, council_nodes) = init_config
            .validate_config_get_genesis(timestamp.get_seconds())
            .expect("Error while validating distribution");

        let mut keys: Vec<StarlingFixedKey> = states.iter().map(|account| account.key()).collect();
        let wrapped: Vec<AccountWrapper> =
            states.iter().map(|st| AccountWrapper(st.clone())).collect();

        let new_account_root = account_storage
            .insert(None, &mut keys, &wrapped)
            .expect("initial insert");

        let genesis_app_hash = compute_app_hash(
            &MerkleTree::empty(),
            &new_account_root,
            &rewards_pool_state,
            &NetworkParameters::Genesis(init_network_params),
        );
        (
            TestEnv {
                dist_coin,
                rewards_pool,
                genesis_app_hash,
                timestamp,
                init_config,
                council_nodes,
                accounts,
            },
            storage,
            account_storage,
        )
    }

    fn chain_node(
        &self,
        storage: Storage,
        account_storage: AccountStorage,
    ) -> ChainNodeApp<MockClient> {
        ChainNodeApp::new_with_storage(
            get_enclave_bridge_mock(),
            &hex::encode_upper(self.genesis_app_hash),
            TEST_CHAIN_ID,
            storage,
            account_storage,
            None,
        )
    }

    fn unbond_tx(&self, coin: Coin, nonce: u64) -> TxAux {
        let tx = UnbondTx::new(
            self.accounts[0].staking_address,
            nonce,
            coin,
            StakedStateOpAttributes::new(0),
        );
        let secp = Secp256k1::new();
        let witness = StakedStateOpWitness::new(get_ecdsa_witness(
            &secp,
            &tx.id(),
            &self.accounts[0].secret_key,
        ));
        TxAux::UnbondStakeTx(tx, witness)
    }

    fn req_init_chain(&self) -> RequestInitChain {
        let share = Coin::new(u64::from(self.dist_coin) / self.accounts.len() as u64).unwrap();
        let validators = self
            .accounts
            .iter()
            .map(|acct| ValidatorUpdate {
                pub_key: Some(PubKey {
                    field_type: "ed25519".to_owned(),
                    data: base64::decode(&acct.validator_pub_key).unwrap(),
                    ..Default::default()
                })
                .into(),
                power: TendermintVotePower::from(share).into(),
                ..Default::default()
            })
            .collect();
        RequestInitChain {
            time: Some(self.timestamp.clone()).into(),
            app_state_bytes: serde_json::to_vec(&self.init_config).unwrap(),
            chain_id: TEST_CHAIN_ID.to_owned(),
            validators,
            ..Default::default()
        }
    }

    fn validator_address(&self, index: usize) -> TendermintValidatorAddress {
        self.council_nodes
            .iter()
            .find(|(address, _)| address == &self.accounts[index].staking_address)
            .expect("council node not found")
            .1
            .consensus_pubkey
            .clone()
            .into()
    }

    fn byzantine_evidence(&self, index: usize) -> Evidence {
        Evidence {
            validator: Some(Validator {
                address: <[u8; 20]>::from(&self.validator_address(index)).to_vec(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }

    fn req_begin_block(&self, height: i64) -> RequestBeginBlock {
        RequestBeginBlock {
            header: Some(Header {
                time: Some(Timestamp::new()).into(),
                chain_id: TEST_CHAIN_ID.to_owned(),
                height,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }

    fn last_commit_info(&self, index: usize, signed_last_block: bool) -> LastCommitInfo {
        LastCommitInfo {
            votes: vec![VoteInfo {
                validator: Some(Validator {
                    address: <[u8; 20]>::from(&self.validator_address(index)).to_vec(),
                    ..Default::default()
                })
                .into(),
                signed_last_block: signed_last_block,
                ..Default::default()
            }]
            .into(),
            ..Default::default()
        }
    }
}

#[test]
fn end_block_should_update_liveness_tracker() {
    // Init Chain
    let (env, storage, account_storage) = TestEnv::new(Coin::max(), Coin::zero(), 1);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&env.req_begin_block(1));

    // Unbond Transaction (this'll change voting power to zero)
    let tx_aux = env.unbond_tx(Coin::new(10_000_000_000).unwrap(), 0);
    let rsp_tx = app.deliver_tx(&RequestDeliverTx {
        tx: tx_aux.encode(),
        ..Default::default()
    });

    assert_eq!(0, rsp_tx.code);
    assert_eq!(
        0,
        i64::from(
            *app.power_changed_in_block
                .get(&env.accounts[0].staking_address)
                .expect("Power did not change after unbonding funds")
        )
    );

    // End Block (this'll remove validator from liveness tracker)
    let validator_address = env.validator_address(0);
    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .validator_liveness
        .contains_key(&validator_address));

    let response_end_block = app.end_block(&RequestEndBlock {
        height: 1,
        ..Default::default()
    });

    assert_eq!(1, response_end_block.validator_updates.to_vec().len());
    assert_eq!(0, response_end_block.validator_updates.to_vec()[0].power);
    // no longer in the current set of validators
    assert!(!app
        .validator_voting_power
        .contains_key(&env.accounts[0].staking_address));
    let zero_key = (TendermintVotePower::zero(), env.accounts[0].staking_address);
    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .council_nodes_by_power
        .contains_key(&zero_key));
    assert!(!app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .validator_liveness
        .contains_key(&validator_address));
}

#[test]
fn begin_block_should_jail_byzantine_validators() {
    // Init Chain
    let (env, storage, account_storage) = TestEnv::new(Coin::max(), Coin::zero(), 1);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp_init_chain = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&RequestBeginBlock {
        byzantine_validators: vec![env.byzantine_evidence(0)].into(),
        ..env.req_begin_block(1)
    });
    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&env.accounts[0].staking_address)
            .unwrap()
    );

    let account = get_account(&env.accounts[0].address, &app);
    assert!(account.is_jailed());
}

#[test]
fn begin_block_should_jail_non_live_validators() {
    // Init Chain
    let (env, storage, account_storage) = TestEnv::new(Coin::max(), Coin::zero(), 1);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp_init_chain = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&RequestBeginBlock {
        last_commit_info: Some(env.last_commit_info(0, false)).into(),
        ..env.req_begin_block(2)
    });

    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&env.accounts[0].staking_address)
            .unwrap()
    );

    let account = get_account(&env.accounts[0].address, &app);
    assert!(account.is_jailed());
}

#[test]
fn begin_block_should_slash_byzantine_validators() {
    // Init Chain
    let (env, storage, account_storage) = TestEnv::new(Coin::max(), Coin::zero(), 1);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp_init_chain = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&RequestBeginBlock {
        byzantine_validators: vec![env.byzantine_evidence(0)].into(),
        ..env.req_begin_block(1)
    });

    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&env.accounts[0].staking_address)
            .unwrap()
    );
    assert!(get_account(&env.accounts[0].address, &app).is_jailed());
    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address));

    // End Block
    app.end_block(&RequestEndBlock::new());
    assert_eq!(
        env.rewards_pool,
        app.last_state.as_ref().unwrap().rewards_pool.remaining
    );

    // Begin Block
    let mut time = Timestamp::new();
    time.seconds = 10;
    let mut req = env.req_begin_block(1);
    req.header.get_mut_ref().time = Some(time).into();
    app.begin_block(&req);

    assert!(!app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address));
    assert_eq!(
        Coin::new((u64::from(env.dist_coin) / 10) * 2).unwrap(), // 0.2 * account_balance
        app.last_state.as_ref().unwrap().rewards_pool.remaining
    );
}

#[test]
fn begin_block_should_slash_non_live_validators() {
    // Init Chain
    let (env, storage, account_storage) = TestEnv::new(Coin::max(), Coin::zero(), 1);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp_init_chain = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&RequestBeginBlock {
        last_commit_info: Some(env.last_commit_info(0, false)).into(),
        ..env.req_begin_block(2)
    });

    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&env.accounts[0].staking_address)
            .unwrap()
    );

    let account = get_account(&env.accounts[0].address, &app);
    assert!(account.is_jailed());
    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address));

    // End Block
    app.end_block(&RequestEndBlock::new());
    assert_eq!(
        env.rewards_pool,
        app.last_state.as_ref().unwrap().rewards_pool.remaining
    );

    // Begin Block
    let mut time = Timestamp::new();
    time.seconds = 10;
    let mut req = env.req_begin_block(1);
    req.header.get_mut_ref().time = Some(time).into();
    app.begin_block(&req);

    assert!(!app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address));
    assert_eq!(
        Coin::new(u64::from(env.dist_coin) / 10).unwrap(), // 0.1 * account_balance
        app.last_state.as_ref().unwrap().rewards_pool.remaining
    );
}

#[test]
fn begin_block_should_update_slash_ratio_for_multiple_punishments() {
    // Init Chain
    let (env, storage, account_storage) = TestEnv::new(Coin::max(), Coin::zero(), 2);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp_init_chain = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&RequestBeginBlock {
        last_commit_info: Some(env.last_commit_info(0, false)).into(),
        ..env.req_begin_block(2)
    });
    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&env.accounts[0].staking_address)
            .unwrap()
    );

    let account = get_account(&env.accounts[0].address, &app);
    assert!(account.is_jailed());

    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address));

    // End Block
    app.end_block(&RequestEndBlock::new());
    assert_eq!(
        Coin::zero(),
        app.last_state.as_ref().unwrap().rewards_pool.remaining
    );

    // Begin Block
    app.begin_block(&RequestBeginBlock {
        byzantine_validators: vec![env.byzantine_evidence(0), env.byzantine_evidence(1)].into(),
        ..env.req_begin_block(1)
    });

    assert!(get_account(&env.accounts[0].address, &app).is_jailed());
    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address));

    // End Block
    app.end_block(&RequestEndBlock::new());
    assert_eq!(
        Coin::zero(),
        app.last_state.as_ref().unwrap().rewards_pool.remaining
    );

    // Begin Block
    let mut time = Timestamp::new();
    time.seconds = 10;
    let mut req = env.req_begin_block(1);
    req.header.get_mut_ref().time = Some(time).into();
    app.begin_block(&req);

    assert!(!app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address));
    assert_eq!(
        Coin::new(u64::from(Coin::max()) / 5).unwrap(), // 0.1 * account_balance
        app.last_state.as_ref().unwrap().rewards_pool.remaining
    );
}

#[test]
fn check_successful_jailing() {
    // Init Chain
    let (env, storage, account_storage) = TestEnv::new(Coin::max(), Coin::zero(), 1);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp_init_chain = app.init_chain(&env.req_init_chain());

    app.jail_account(env.accounts[0].staking_address, PunishmentKind::NonLive)
        .expect("Unable to jail account");

    let account = get_account(&env.accounts[0].address, &app);
    assert!(account.is_jailed());
    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&env.accounts[0].staking_address)
            .unwrap()
    );
}
