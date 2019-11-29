use std::collections::BTreeMap;
use std::convert::TryInto;

use abci::*;
use enclave_protocol::{EnclaveRequest, EnclaveResponse};
use kvdb::DBTransaction;
use log::{info, warn};
use parity_scale_codec::{Decode, Encode};
use protobuf::Message;
use serde::{Deserialize, Serialize};

use crate::enclave_bridge::EnclaveProxy;
use crate::liveness::LivenessTracker;
use crate::punishment::ValidatorPunishment;
use crate::storage::account::AccountWrapper;
use crate::storage::account::{pure_account_storage, AccountStorage};
use crate::storage::tx::get_account;
use crate::storage::tx::StarlingFixedKey;
use crate::storage::*;
use chain_core::common::MerkleTree;
use chain_core::common::Timespec;
use chain_core::common::{H256, HASH_SIZE_256};
use chain_core::compute_app_hash;
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::init::config::InitConfig;
use chain_core::init::config::NetworkParameters;
use chain_core::state::account::StakedStateDestination;
use chain_core::state::account::{CouncilNode, StakedState, StakedStateAddress};
use chain_core::state::tendermint::{BlockHeight, TendermintValidatorAddress, TendermintVotePower};
use chain_core::state::RewardsPoolState;
use chain_core::tx::TxAux;

/// Validator state tracking
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Encode, Decode, Default)]
pub struct ValidatorState {
    /// all nodes (current validator set + pending): TendermintVotePower == coin bonded amount if >= minimal
    /// or TendermintVotePower == 0 if < minimal or was jailed
    /// FIXME: delete node metadata if voting power == 0 for longer than unbonding time
    pub council_nodes_by_power: BTreeMap<(TendermintVotePower, StakedStateAddress), CouncilNode>,
    /// stores staking account address corresponding to tendermint validator addresses
    /// FIXME: delete node metadata if voting power == 0 for longer than unbonding time
    pub tendermint_validator_addresses: BTreeMap<TendermintValidatorAddress, StakedStateAddress>,
    /// Runtime state for computing and executing validator punishment
    pub punishment: ValidatorPunishment,
}

impl ValidatorState {
    /// add validator for tracking if it wasn't added before
    pub fn add_validator_for_tracking(
        &mut self,
        validator_address: TendermintValidatorAddress,
        staking_address: StakedStateAddress,
        block_signing_window: u16,
    ) {
        if !self
            .punishment
            .validator_liveness
            .contains_key(&validator_address)
        {
            self.tendermint_validator_addresses
                .insert(validator_address.clone(), staking_address);
            self.punishment.validator_liveness.insert(
                validator_address,
                LivenessTracker::new(block_signing_window),
            );
        }
    }

    /// remove from tracking liveness
    pub fn remove_validator_from_tracking(
        &mut self,
        tendermint_address: &TendermintValidatorAddress,
    ) {
        self.punishment
            .validator_liveness
            .remove(tendermint_address);
    }
}

/// ABCI app state snapshot
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Encode, Decode)]
pub struct ChainNodeState {
    /// last processed block height
    pub last_block_height: BlockHeight,
    /// last committed merkle root
    pub last_apphash: H256,
    /// time in previous block's header or genesis time
    pub block_time: Timespec,
    /// root hash of the sparse merkle patricia trie of staking account states
    pub last_account_root_hash: StarlingFixedKey,
    /// last rewards pool state
    pub rewards_pool: RewardsPoolState,
    /// Record how many block each validator proposed, used for rewards distribution,
    /// cleared after rewards distributed
    pub proposer_stats: BTreeMap<StakedStateAddress, u64>,
    /// network parameters (fee policy, staking configuration etc.)
    pub network_params: NetworkParameters,
    /// state of validators (keys, voting power, punishments, rewards...)
    #[serde(skip)]
    pub validators: ValidatorState,
    /// genesis time
    pub genesis_time: Timespec,
}

impl ChainNodeState {
    pub fn genesis(
        genesis_apphash: H256,
        genesis_time: Timespec,
        last_account_root_hash: StarlingFixedKey,
        rewards_pool: RewardsPoolState,
        network_params: NetworkParameters,
        validators: ValidatorState,
    ) -> Self {
        ChainNodeState {
            last_block_height: 0,
            last_apphash: genesis_apphash,
            block_time: genesis_time,
            last_account_root_hash,
            rewards_pool,
            proposer_stats: BTreeMap::new(),
            network_params,
            validators,
            genesis_time,
        }
    }
}

/// The global ABCI state
pub struct ChainNodeApp<T: EnclaveProxy> {
    /// the underlying key-value storage (+ possibly some info in the future)
    pub storage: Storage,
    /// account trie storage
    pub accounts: AccountStorage,
    /// valid transactions after DeliverTx before EndBlock/Commit
    pub delivered_txs: Vec<TxAux>,
    /// root hash of the sparse merkle patricia trie of staking account states after DeliverTx before EndBlock/Commit
    pub uncommitted_account_root_hash: StarlingFixedKey,
    /// a reference to genesis (used when there is no committed state)
    pub genesis_app_hash: H256,
    /// last two hex digits in chain_id
    pub chain_hex_id: u8,
    /// last application state snapshot (if any)
    pub last_state: Option<ChainNodeState>,
    /// validator voting power (current validator set)
    pub validator_voting_power: BTreeMap<StakedStateAddress, TendermintVotePower>,
    /// new validator addresses or whose bonded amount changed in the current block
    pub power_changed_in_block: BTreeMap<StakedStateAddress, TendermintVotePower>,
    /// new nodes proposed in the block
    pub new_nodes_in_block: BTreeMap<StakedStateAddress, CouncilNode>,
    /// proxy for processing transaction validation requests
    pub tx_validator: T,
    /// was rewards pool updated in the current block?
    pub rewards_pool_updated: bool,
    /// address of tx query enclave to supply to clients (if any)
    pub tx_query_address: Option<String>,
}

pub fn get_validator_key(node: &CouncilNode) -> PubKey {
    let mut pk = PubKey::new();
    let (keytype, key) = node.consensus_pubkey.to_validator_update();
    pk.set_field_type(keytype);
    pk.set_data(key);
    pk
}

fn get_validator_mapping(
    accounts: &AccountStorage,
    last_app_state: &ChainNodeState,
) -> BTreeMap<StakedStateAddress, TendermintVotePower> {
    let mut validator_voting_power = BTreeMap::new();
    for ((voting_power, address), node) in last_app_state
        .validators
        .council_nodes_by_power
        .iter()
        .rev()
        .take(last_app_state.network_params.get_max_validators())
    {
        // integrity checks -- committed / disk-persisted values should match up
        let account = get_account(&address, &last_app_state.last_account_root_hash, accounts)
            .expect("council node staking state address should be in the state trie");
        assert!(
            &account.council_node.is_some(),
            "council node's staking state should contain it"
        );
        if account.is_jailed()
            || account.bonded
                < last_app_state
                    .network_params
                    .get_required_council_node_stake()
        {
            let vp = TendermintVotePower::from(Coin::zero());
            assert!(
                voting_power == &vp,
                "jailed or below minimum bonded amounts should have 0 voting power"
            );
            validator_voting_power.insert(*address, vp);
        } else {
            let vp = TendermintVotePower::from(account.bonded);
            assert!(
                voting_power == &vp,
                "voting power should match the bonded amount"
            );
            validator_voting_power.insert(*address, vp);
        }
        assert!(
            node == &account.council_node.unwrap(),
            "council node should match the one in the state trie"
        );
    }
    validator_voting_power
}

fn check_and_store_consensus_params(
    init_consensus_params: Option<&ConsensusParams>,
    _validators: &[(StakedStateAddress, CouncilNode)],
    _network_params: &NetworkParameters,
    inittx: &mut DBTransaction,
) {
    match init_consensus_params {
        Some(cp) => {
            // TODO: check validators only used allowed key types
            // TODO: check unbonding period == cp.evidence.max_age
            // NOTE: cp.evidence.max_age is currently in the number of blocks
            // but it should be migrated to "time", in which case this check will make sense
            // (as unbonding time is in seconds, not blocks)
            warn!("consensus parameters not checked (TODO)");
            inittx.put(
                COL_EXTRA,
                b"init_chain_consensus_params",
                &(cp as &dyn Message)
                    .write_to_bytes()
                    .expect("consensus params"),
            );
        }
        None => {
            info!("consensus params not in the initchain request");
        }
    }
}

fn get_voting_power(
    distribution: &BTreeMap<RedeemAddress, (StakedStateDestination, Coin)>,
    node_address: &StakedStateAddress,
) -> TendermintVotePower {
    match node_address {
        StakedStateAddress::BasicRedeem(a) => TendermintVotePower::from(distribution[a].1),
    }
}

fn store_valid_genesis_state(genesis_state: &ChainNodeState, inittx: &mut DBTransaction) {
    let encoded = genesis_state.encode();
    inittx.put(COL_NODE_INFO, LAST_STATE_KEY, &encoded);
    inittx.put(COL_EXTRA, b"init_chain_state", &encoded);
}

fn compute_accounts_root(account_storage: &mut AccountStorage, accounts: &[StakedState]) -> H256 {
    let mut keys: Vec<_> = accounts.iter().map(StakedState::key).collect();
    let wrapped: Vec<_> = accounts.iter().cloned().map(AccountWrapper).collect();
    account_storage
        .insert(None, &mut keys, &wrapped)
        .expect("insert failed")
}

pub fn init_app_hash(conf: &InitConfig, genesis_time: Timespec) -> H256 {
    let (accounts, rp, _nodes) = conf
        .validate_config_get_genesis(genesis_time)
        .expect("distribution validation error");

    compute_app_hash(
        &MerkleTree::empty(),
        &compute_accounts_root(&mut pure_account_storage(20).unwrap(), &accounts),
        &rp,
        &NetworkParameters::Genesis(conf.network_params.clone()),
    )
}

impl<T: EnclaveProxy> ChainNodeApp<T> {
    fn restore_from_storage(
        tx_validator: T,
        last_app_state: ChainNodeState,
        genesis_app_hash: [u8; HASH_SIZE_256],
        chain_id: &str,
        storage: Storage,
        accounts: AccountStorage,
        tx_query_address: Option<String>,
    ) -> Self {
        let stored_gah = storage
            .db
            .get(COL_NODE_INFO, GENESIS_APP_HASH_KEY)
            .expect("genesis hash lookup")
            .expect("last app state found, but genesis app hash not stored");
        let mut stored_genesis = [0u8; HASH_SIZE_256];
        stored_genesis.copy_from_slice(&stored_gah[..]);

        if stored_genesis != genesis_app_hash {
            panic!(
                "stored genesis app hash: {} does not match the provided genesis app hash: {}",
                hex::encode(stored_genesis),
                hex::encode(genesis_app_hash)
            );
        }
        let stored_chain_id = storage
            .db
            .get(COL_EXTRA, CHAIN_ID_KEY)
            .expect("chain id lookup")
            .expect("last app state found, but no chain id stored");
        if stored_chain_id != chain_id.as_bytes() {
            panic!(
                "stored chain id: {:?} does not match the provided chain id: {:?}",
                stored_chain_id, chain_id
            );
        }
        let chain_hex_id = hex::decode(&chain_id[chain_id.len() - 2..])
            .expect("failed to decode two last hex digits in chain ID")[0];

        let validator_voting_power = get_validator_mapping(&accounts, &last_app_state);
        ChainNodeApp {
            storage,
            accounts,
            delivered_txs: Vec::new(),
            uncommitted_account_root_hash: last_app_state.last_account_root_hash,
            chain_hex_id,
            genesis_app_hash,
            last_state: Some(last_app_state),
            validator_voting_power,
            power_changed_in_block: BTreeMap::new(),
            new_nodes_in_block: BTreeMap::new(),
            tx_validator,
            rewards_pool_updated: false,
            tx_query_address,
        }
    }

    /// Creates a new App initialized with a given storage (could be in-mem or persistent).
    /// If persistent storage is used, it'll try to recover stored arguments (e.g. last app hash / block height) from it.
    ///
    /// # Arguments
    ///
    /// * `tx_validator` - ZMQ proxy to enclave TX validator
    /// * `gah` - hex-encoded genesis app hash
    /// * `chain_id` - the chain ID set in Tendermint genesis.json (our name convention is that the last two characters should be hex digits)
    /// * `storage` - underlying storage to be used (in-mem or persistent)
    /// * `accounts` - underlying storage for account tries to be used (in-mem or persistent)
    /// * `tx_query_address` -  address of tx query enclave to supply to clients (if any)
    pub fn new_with_storage(
        mut tx_validator: T,
        gah: &str,
        chain_id: &str,
        storage: Storage,
        accounts: AccountStorage,
        tx_query_address: Option<String>,
    ) -> Self {
        let decoded_gah = hex::decode(gah).expect("failed to decode genesis app hash");
        let mut genesis_app_hash = [0u8; HASH_SIZE_256];
        genesis_app_hash.copy_from_slice(&decoded_gah[..]);
        let chain_hex_id = hex::decode(&chain_id[chain_id.len() - 2..])
            .expect("failed to decode two last hex digits in chain ID")[0];

        if let Some(last_app_state) = storage
            .db
            .get(COL_NODE_INFO, LAST_STATE_KEY)
            .expect("app state lookup")
        {
            info!("last app state stored");
            let data = last_app_state.to_vec();
            let last_state =
                ChainNodeState::decode(&mut data.as_slice()).expect("deserialize app state");
            // TODO: genesis app hash check when embedded in enclave binary
            let enclave_sanity_check = tx_validator.process_request(EnclaveRequest::CheckChain {
                chain_hex_id,
                last_app_hash: Some(last_state.last_apphash),
            });
            match enclave_sanity_check {
                EnclaveResponse::CheckChain(Ok(_)) => {
                    info!("enclave connection OK");
                }
                EnclaveResponse::CheckChain(Err(enc_app)) => {
                    let enc_app_str = match enc_app {
                        None => "None".to_string(),
                        Some(data) => hex::encode(data),
                    };
                    panic!("enclave sanity check failed (either a binary for a different network is used or there is a problem with enclave process), \
                    enclave app hash: {} (chain-abci app hash: {})", enc_app_str, hex::encode(last_state.last_apphash));
                }
                _ => unreachable!("unexpected enclave response"),
            }

            ChainNodeApp::restore_from_storage(
                tx_validator,
                last_state,
                genesis_app_hash,
                chain_id,
                storage,
                accounts,
                tx_query_address,
            )
        } else {
            info!("no last app state stored");
            // TODO: genesis app hash check when embedded in enclave binary
            let enclave_sanity_check = tx_validator.process_request(EnclaveRequest::CheckChain {
                chain_hex_id,
                last_app_hash: None,
            });
            match enclave_sanity_check {
                EnclaveResponse::CheckChain(Ok(_)) => {
                    info!("enclave connection OK");
                }
                EnclaveResponse::CheckChain(Err(enc_app)) => {
                    let enc_app_str = match enc_app {
                        None => "None".to_string(),
                        Some(data) => hex::encode(data),
                    };
                    panic!("enclave sanity check failed (either a binary for a different network is used or there is a problem with enclave process), \
                    enclave app hash: {}", enc_app_str);
                }
                _ => unreachable!("unexpected enclave response"),
            }
            let mut inittx = storage.db.transaction();
            inittx.put(COL_NODE_INFO, GENESIS_APP_HASH_KEY, &genesis_app_hash);
            inittx.put(COL_EXTRA, CHAIN_ID_KEY, chain_id.as_bytes());
            storage
                .db
                .write(inittx)
                .expect("genesis app hash should be stored");
            ChainNodeApp {
                storage,
                accounts,
                delivered_txs: Vec::new(),
                uncommitted_account_root_hash: [0u8; 32],
                chain_hex_id,
                genesis_app_hash,
                last_state: None,
                validator_voting_power: BTreeMap::new(),
                power_changed_in_block: BTreeMap::new(),
                new_nodes_in_block: BTreeMap::new(),
                tx_validator,
                rewards_pool_updated: false,
                tx_query_address,
            }
        }
    }

    /// Creates a new App initialized according to a provided storage config (most likely persistent).
    ///
    /// # Arguments
    ///
    /// * `tx_validator` - ZMQ proxy to enclave TX validator
    /// * `gah` - hex-encoded genesis app hash
    /// * `chain_id` - the chain ID set in Tendermint genesis.json (our name convention is that the last two characters should be hex digits)
    /// * `node_storage_config` - configuration for node storage (currently only the path, but TODO: more options, e.g. SSD or HDD params)
    /// * `account_storage_config` - configuration for account storage
    /// * `tx_query_address` -  address of tx query enclave to supply to clients (if any)
    pub fn new(
        tx_validator: T,
        gah: &str,
        chain_id: &str,
        node_storage_config: &StorageConfig<'_>,
        account_storage_config: &StorageConfig<'_>,
        tx_query_address: Option<String>,
    ) -> ChainNodeApp<T> {
        ChainNodeApp::new_with_storage(
            tx_validator,
            gah,
            chain_id,
            Storage::new(node_storage_config),
            AccountStorage::new(Storage::new(account_storage_config), 20).expect("account db"),
            tx_query_address,
        )
    }

    /// Handles InitChain requests:
    /// should validate initial genesis distribution, initialize everything in the key-value DB and check it matches the expected values
    /// provided as arguments.
    pub fn init_chain_handler(&mut self, req: &RequestInitChain) -> ResponseInitChain {
        let db = &self.storage.db;
        let conf: InitConfig =
            serde_json::from_slice(&req.app_state_bytes).expect("failed to parse initial config");

        let genesis_time = req
            .time
            .as_ref()
            .expect("missing genesis time")
            .get_seconds()
            .try_into()
            .expect("invalid genesis time");
        let (accounts, rp, nodes) = conf
            .validate_config_get_genesis(genesis_time)
            .expect("distribution validation error");

        let stored_chain_id = db
            .get(COL_EXTRA, CHAIN_ID_KEY)
            .unwrap()
            .expect("last app hash found, but no chain id stored");
        if stored_chain_id != req.chain_id.as_bytes() {
            panic!(
                "stored chain id: {} does not match the provided chain id: {}",
                String::from_utf8(stored_chain_id.to_vec()).unwrap(),
                req.chain_id
            );
        }

        let network_params = NetworkParameters::Genesis(conf.network_params);
        let new_account_root = compute_accounts_root(&mut self.accounts, &accounts);
        let genesis_app_hash = compute_app_hash(
            &MerkleTree::empty(),
            &new_account_root,
            &rp,
            &network_params,
        );

        if self.genesis_app_hash != genesis_app_hash {
            panic!("initchain resulting genesis app hash: {} does not match the expected genesis app hash: {}", hex::encode(genesis_app_hash), hex::encode(self.genesis_app_hash));
        }

        let mut inittx = db.transaction();
        check_and_store_consensus_params(
            req.consensus_params.as_ref(),
            &nodes,
            &network_params,
            &mut inittx,
        );

        let mut validators = Vec::with_capacity(nodes.len());
        let mut validator_liveness = BTreeMap::new();
        let mut validator_by_voting_power = BTreeMap::new();
        let mut tendermint_validator_addresses = BTreeMap::new();

        for (address, node) in nodes.iter() {
            let mut validator = ValidatorUpdate::default();
            let power = get_voting_power(&conf.distribution, address);
            self.validator_voting_power.insert(*address, power);
            validator_by_voting_power.insert((power, *address), node.clone());
            validator.set_power(power.into());
            let pk = get_validator_key(&node);
            validator.set_pub_key(pk);
            validators.push(validator);

            let tendermint_validator_address =
                TendermintValidatorAddress::from(&node.consensus_pubkey);

            tendermint_validator_addresses.insert(tendermint_validator_address.clone(), *address);

            validator_liveness.insert(
                tendermint_validator_address,
                LivenessTracker::new(network_params.get_block_signing_window()),
            );
        }

        // check req.validators is consistent with app_state's council nodes
        let mut req_validators = req.validators.clone().into_vec();
        let fn_sort_key = |a: &ValidatorUpdate| {
            a.pub_key
                .as_ref()
                .map(|key| (key.field_type.clone(), key.data.clone()))
        };
        validators.sort_by_key(fn_sort_key);
        req_validators.sort_by_key(fn_sort_key);
        if validators != req_validators {
            panic!("validators in genesis configuration are not consistent with app_state");
        }

        let genesis_state = ChainNodeState::genesis(
            genesis_app_hash,
            genesis_time,
            new_account_root,
            rp,
            network_params,
            ValidatorState {
                council_nodes_by_power: validator_by_voting_power,
                tendermint_validator_addresses,
                punishment: ValidatorPunishment {
                    validator_liveness,
                    slashing_schedule: Default::default(),
                },
            },
        );
        store_valid_genesis_state(&genesis_state, &mut inittx);

        let wr = self.storage.db.write(inittx);
        if wr.is_err() {
            panic!("db write error: {}", wr.err().unwrap());
        } else {
            self.uncommitted_account_root_hash = genesis_state.last_account_root_hash;
            self.last_state = Some(genesis_state);
        }

        ResponseInitChain::new()
    }
}
