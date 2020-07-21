use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::mem;

use abci::*;
use log::{info, warn};
use parity_scale_codec::{Decode, Encode};
use protobuf::Message;
use serde::{Deserialize, Serialize};

#[cfg(all(
    not(feature = "mock-enclave"),
    not(feature = "legacy"),
    feature = "edp",
    target_os = "linux"
))]
use crate::enclave_bridge::edp::start_zmq;
#[cfg(all(not(feature = "mock-enclave"), feature = "legacy", target_os = "linux"))]
use crate::enclave_bridge::real::start_zmq;
use crate::enclave_bridge::EnclaveProxy;
use crate::staking::StakingTable;
use chain_core::common::MerkleTree;
use chain_core::common::Timespec;
use chain_core::common::{H256, HASH_SIZE_256};
use chain_core::compute_app_hash;
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::init::config::InitConfig;
use chain_core::init::config::NetworkParameters;
use chain_core::state::account::StakedStateDestination;
use chain_core::state::account::{CouncilNodeMeta, StakedStateAddress};
use chain_core::state::tendermint::{BlockHeight, TendermintVotePower};
use chain_core::state::{ChainState, RewardsPoolState};
use chain_core::tx::TxAux;
use chain_core::ChainInfo;
use chain_storage::buffer::{
    flush_storage, GetStaking, KVBuffer, StakingBuffer, StoreKV, StoreStaking,
};
use chain_storage::jellyfish::{compute_staking_root, sum_staking_coins, StakingGetter, Version};
use chain_storage::{Storage, StoredChainState};

/// ABCI app state snapshot
#[derive(Serialize, Deserialize, Clone, Encode, Decode)]
pub struct ChainNodeState {
    /// last processed block height, set in end block
    pub last_block_height: BlockHeight,
    /// last committed merkle root
    pub last_apphash: H256,
    /// time in current block's header or genesis time, set in begin block
    pub block_time: Timespec,
    /// current block's height or 0 for genesis, set in begin block
    pub block_height: BlockHeight,
    /// Indexings of validator states
    #[serde(skip)]
    pub staking_table: StakingTable,
    /// genesis time
    pub genesis_time: Timespec,
    /// max evidence age from consensus parameter
    pub max_evidence_age: Timespec,
    /// Version number of staking merkle tree
    pub staking_version: Version,
    /// Record the sum of all the coins in UTxO set
    pub utxo_coins: Coin,
    /// Record the biggest enclave ISVSVN (Security Version Number of the Enclave) we've seen in
    /// keypackage so far
    pub enclave_isv_svn: u16,

    /// The parts of states which involved in computing app_hash
    pub top_level: ChainState,
}

impl StoredChainState for ChainNodeState {
    fn get_encoded(&self) -> Vec<u8> {
        self.encode()
    }

    fn get_encoded_top_level(&self) -> Vec<u8> {
        self.top_level.encode()
    }

    fn get_last_app_hash(&self) -> H256 {
        self.last_apphash
    }

    fn get_staking_version(&self) -> Version {
        self.staking_version
    }
}

impl ChainNodeState {
    #[allow(clippy::too_many_arguments)]
    pub fn genesis(
        genesis_apphash: H256,
        genesis_time: Timespec,
        max_evidence_age: Timespec,
        account_root: H256,
        rewards_pool: RewardsPoolState,
        network_params: NetworkParameters,
        staking_table: StakingTable,
        enclave_isv_svn: u16,
    ) -> Self {
        ChainNodeState {
            last_block_height: BlockHeight::genesis(),
            last_apphash: genesis_apphash,
            block_time: genesis_time,
            block_height: BlockHeight::genesis(),
            staking_table,
            genesis_time,
            max_evidence_age,
            staking_version: 0,
            utxo_coins: Coin::zero(),
            enclave_isv_svn,
            top_level: ChainState {
                account_root,
                rewards_pool,
                network_params,
            },
        }
    }

    pub fn get_unbonding_period(&self) -> Timespec {
        self.max_evidence_age
    }
}

/// Two types of storage buffer
pub enum BufferType {
    Consensus,
    Mempool,
}

/// The global ABCI state
pub struct ChainNodeApp<T: EnclaveProxy> {
    /// the underlying key-value storage (+ possibly some info in the future)
    pub storage: Storage,
    /// valid transactions after DeliverTx before EndBlock/Commit
    pub delivered_txs: Vec<TxAux>,
    /// a reference to genesis (used when there is no committed state)
    pub genesis_app_hash: H256,
    /// last two hex digits in chain_id
    pub chain_hex_id: u8,
    /// last application state snapshot (if any)
    pub last_state: Option<ChainNodeState>,
    /// The state for mempool connection
    pub mempool_state: Option<ChainNodeState>,
    /// proxy for processing transaction validation requests
    pub tx_validator: T,
    /// was rewards pool updated in the current block?
    pub rewards_pool_updated: bool,
    /// address of tx query enclave to supply to clients (if any)
    pub tx_query_address: Option<String>,

    /// consensus buffer of staking merkle trie storage
    pub staking_buffer: StakingBuffer,
    /// mempool buffer of staking merkle trie storage
    pub mempool_staking_buffer: StakingBuffer,
    /// consensus buffer of key-value storage
    pub kv_buffer: KVBuffer,
    /// mempool buffer of key-value storage
    pub mempool_kv_buffer: KVBuffer,
}

pub fn get_validator_key(node: &CouncilNodeMeta) -> PubKey {
    let mut pk = PubKey::new();
    let (keytype, key) = node.consensus_pubkey.to_validator_update();
    pk.set_field_type(keytype);
    pk.set_data(key);
    pk
}

fn check_and_store_consensus_params(
    init_consensus_params: Option<&ConsensusParams>,
    _validators: &[(StakedStateAddress, CouncilNodeMeta)],
    _network_params: &NetworkParameters,
    storage: &mut Storage,
) {
    match init_consensus_params {
        Some(cp) => {
            // TODO: check validators only used allowed key types
            // TODO: check unbonding period == cp.evidence.max_age
            // NOTE: cp.evidence.max_age is currently in the number of blocks
            // but it should be migrated to "time", in which case this check will make sense
            // (as unbonding time is in seconds, not blocks)
            warn!("consensus parameters not checked (TODO)");
            storage.store_consensus_params(
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

/// checks InitChain's req.validators is consistent with InitChain's app_state's council nodes
pub fn check_validators(
    nodes: &[(StakedStateAddress, CouncilNodeMeta)],
    mut req_validators: Vec<ValidatorUpdate>,
    distribution: &BTreeMap<RedeemAddress, (StakedStateDestination, Coin)>,
) -> Result<(), ()> {
    let mut validators = Vec::with_capacity(nodes.len());
    for (address, node) in nodes.iter() {
        let mut validator = ValidatorUpdate::default();
        let power = get_voting_power(distribution, address);
        validator.set_power(power.into());
        let pk = get_validator_key(&node);
        validator.set_pub_key(pk);
        validators.push(validator);
    }

    let fn_sort_key = |a: &ValidatorUpdate| {
        a.pub_key
            .as_ref()
            .map(|key| (key.field_type.clone(), key.data.clone()))
    };
    validators.sort_by_key(fn_sort_key);
    req_validators.sort_by_key(fn_sort_key);

    if validators == req_validators {
        Ok(())
    } else {
        Err(())
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

pub fn init_app_hash(conf: &InitConfig, genesis_time: Timespec) -> H256 {
    let state = conf
        .validate_config_get_genesis(genesis_time)
        .expect("distribution validation error");

    compute_app_hash(
        &MerkleTree::empty(),
        &compute_staking_root(&state.accounts),
        &state.rewards_pool,
        &NetworkParameters::Genesis(conf.network_params.clone()),
    )
}

impl<T: EnclaveProxy + 'static> ChainNodeApp<T> {
    fn restore_from_storage(
        tx_validator: T,
        last_app_state: ChainNodeState,
        genesis_app_hash: [u8; HASH_SIZE_256],
        chain_id: &str,
        storage: Storage,
        tx_query_address: Option<String>,
    ) -> Self {
        let stored_genesis = storage.get_genesis_app_hash();

        if stored_genesis != genesis_app_hash {
            panic!(
                "stored genesis app hash: {} does not match the provided genesis app hash: {}",
                hex::encode(stored_genesis),
                hex::encode(genesis_app_hash)
            );
        }
        let stored_chain_id = storage.get_stored_chain_id();
        if stored_chain_id != chain_id.as_bytes() {
            panic!(
                "stored chain id: {:?} does not match the provided chain id: {:?}",
                stored_chain_id, chain_id
            );
        }
        let chain_hex_id = hex::decode(&chain_id[chain_id.len() - 2..])
            .expect("failed to decode two last hex digits in chain ID")[0];

        ChainNodeApp {
            storage,
            delivered_txs: Vec::new(),
            chain_hex_id,
            genesis_app_hash,
            last_state: Some(last_app_state.clone()),
            mempool_state: Some(last_app_state),
            tx_validator,
            rewards_pool_updated: false,
            tx_query_address,

            staking_buffer: HashMap::new(),
            mempool_staking_buffer: HashMap::new(),
            kv_buffer: HashMap::new(),
            mempool_kv_buffer: HashMap::new(),
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
    /// * `tx_query_address` -  address of tx query enclave to supply to clients (if any)
    /// * `enclave_server` -  connection string which ZeroMQ server wrapper around the transaction validation enclave will listen on
    pub fn new_with_storage(
        mut tx_validator: T,
        gah: &str,
        chain_id: &str,
        mut storage: Storage,
        tx_query_address: Option<String>,
        enclave_server: Option<String>,
    ) -> Self {
        let decoded_gah = hex::decode(gah).expect("failed to decode genesis app hash");
        let mut genesis_app_hash = [0u8; HASH_SIZE_256];
        genesis_app_hash.copy_from_slice(&decoded_gah[..]);
        let chain_hex_id = hex::decode(&chain_id[chain_id.len() - 2..])
            .expect("failed to decode two last hex digits in chain ID")[0];

        if let (Some(_), Some(_conn_str)) = (tx_query_address.as_ref(), enclave_server.as_ref()) {
            #[cfg(all(not(feature = "mock-enclave"), feature = "legacy", target_os = "linux"))]
            let _ = start_zmq(_conn_str, chain_hex_id, storage.get_read_only());
            #[cfg(all(
                not(feature = "mock-enclave"),
                not(feature = "legacy"),
                feature = "edp",
                target_os = "linux"
            ))]
            let _ = start_zmq(
                tx_validator.clone(),
                _conn_str,
                chain_hex_id,
                storage.get_read_only(),
            );
        }

        if let Some(data) = storage.get_last_app_state() {
            info!("last app state stored");
            let mut last_state =
                ChainNodeState::decode(&mut data.as_slice()).expect("deserialize app state");

            // if tx-query address wasn't provided first time,
            // then it shouldn't be provided on another run, and vice versa
            let last_stored_height = storage.get_historical_state(last_state.last_block_height);

            if last_stored_height.is_some() {
                info!("historical data is stored");
                if tx_query_address.is_none() {
                    panic!("tx-query address is needed, or delete chain-abci data and tx-validation data before run");
                }
            } else {
                info!("no historical data is stored");
                if tx_query_address.is_some() {
                    panic!("tx-query address is not needed, or delete chain-abci data and tx-validation data before run");
                }
            }

            // TODO: genesis app hash check when embedded in enclave binary
            let enclave_sanity_check = tx_validator.check_chain(chain_hex_id);
            match enclave_sanity_check {
                Ok(_) => {
                    info!("enclave connection OK");
                }
                Err(()) => {
                    panic!("enclave sanity check failed (either a binary for a different network is used or there is a problem with enclave process)");
                }
            }

            // populate the indexing structures in staking table.
            last_state.staking_table.initialize(
                &StakingGetter::new(&storage, last_state.staking_version),
                last_state
                    .top_level
                    .network_params
                    .get_required_council_node_stake(),
            );
            ChainNodeApp::restore_from_storage(
                tx_validator,
                last_state,
                genesis_app_hash,
                chain_id,
                storage,
                tx_query_address,
            )
        } else {
            info!("no last app state stored");
            // TODO: genesis app hash check when embedded in enclave binary
            let enclave_sanity_check = tx_validator.check_chain(chain_hex_id);
            match enclave_sanity_check {
                Ok(_) => {
                    info!("enclave connection OK");
                }
                Err(()) => {
                    panic!("enclave sanity check failed (either a binary for a different network is used or there is a problem with enclave process)");
                }
            }
            storage.write_genesis_chain_id(&genesis_app_hash, chain_id);
            ChainNodeApp {
                storage,
                delivered_txs: Vec::new(),
                chain_hex_id,
                genesis_app_hash,
                last_state: None,
                mempool_state: None,
                tx_validator,
                rewards_pool_updated: false,
                tx_query_address,

                staking_buffer: HashMap::new(),
                mempool_staking_buffer: HashMap::new(),
                kv_buffer: HashMap::new(),
                mempool_kv_buffer: HashMap::new(),
            }
        }
    }

    /// Handles InitChain requests:
    /// should validate initial genesis distribution, initialize everything in the key-value DB and check it matches the expected values
    /// provided as arguments.
    pub fn init_chain_handler(&mut self, req: &RequestInitChain) -> ResponseInitChain {
        let max_evidence_age = req
            .consensus_params
            .as_ref()
            .and_then(|params| {
                params.evidence.as_ref().and_then(|evidence| {
                    evidence
                        .max_age_duration
                        .as_ref()
                        .and_then(|duration| duration.seconds.try_into().ok())
                })
            })
            .expect("No valid max_evidence_age");
        let conf: InitConfig =
            serde_json::from_slice(&req.app_state_bytes).expect("failed to parse initial config");

        let genesis_time = req
            .time
            .as_ref()
            .expect("missing genesis time")
            .get_seconds()
            .try_into()
            .expect("invalid genesis time");
        let state = conf
            .validate_config_get_genesis(genesis_time)
            .expect("distribution validation error");

        let stored_chain_id = self.storage.get_stored_chain_id();
        if stored_chain_id != req.chain_id.as_bytes() {
            panic!(
                "stored chain id: {} does not match the provided chain id: {}",
                String::from_utf8(stored_chain_id.to_vec()).unwrap(),
                req.chain_id
            );
        }

        let network_params = NetworkParameters::Genesis(conf.network_params);
        let new_account_root = self.storage.put_stakings(0, &state.accounts);
        let genesis_app_hash = compute_app_hash(
            &MerkleTree::empty(),
            &new_account_root,
            &state.rewards_pool,
            &network_params,
        );

        if self.genesis_app_hash != genesis_app_hash {
            panic!("initchain resulting genesis app hash: {} does not match the expected genesis app hash: {}", hex::encode(genesis_app_hash), hex::encode(self.genesis_app_hash));
        }

        check_and_store_consensus_params(
            req.consensus_params.as_ref(),
            &state.validators,
            &network_params,
            &mut self.storage,
        );

        check_validators(
            &state.validators,
            req.validators.clone().into_vec(),
            &conf.distribution,
        )
        .expect("validators in genesis configuration are not consistent with app_state");

        let val_addresses = state
            .validators
            .iter()
            .map(|(addr, _)| *addr)
            .collect::<Vec<_>>();
        let staking_table = StakingTable::from_genesis(
            &staking_getter!(self, 0),
            network_params.get_required_council_node_stake(),
            network_params.get_max_validators(),
            &val_addresses,
        );

        let genesis_state = ChainNodeState::genesis(
            genesis_app_hash,
            genesis_time,
            max_evidence_age,
            new_account_root,
            state.rewards_pool,
            network_params,
            staking_table,
            state.isv_svn,
        );
        chain_storage::store_genesis_state(
            &mut kv_store!(self),
            &genesis_state,
            self.tx_query_address.is_some(),
        );
        flush_storage(&mut self.storage, mem::take(&mut self.kv_buffer)).expect("storage io error");

        self.last_state = Some(genesis_state);
        self.mempool_state = self.last_state.clone();
        ResponseInitChain::new()
    }

    pub fn staking_store(&mut self, buffer_type: BufferType) -> impl StoreStaking + '_ {
        let version = self
            .last_state
            .as_ref()
            .map(|state| state.staking_version)
            .unwrap_or(0);
        staking_store!(self, version, buffer_type)
    }

    pub fn staking_getter(&self, buffer_type: BufferType) -> impl GetStaking + '_ {
        let version = self
            .last_state
            .as_ref()
            .map(|state| state.staking_version)
            .unwrap_or(0);
        staking_getter!(self, version, buffer_type)
    }

    pub fn staking_getter_committed(&self) -> StakingGetter<'_, Storage> {
        StakingGetter::new(
            &self.storage,
            self.last_state
                .as_ref()
                .map(|state| state.staking_version)
                .unwrap_or(0),
        )
    }

    pub fn kv_store(&mut self, buffer_type: BufferType) -> impl StoreKV + '_ {
        kv_store!(self, buffer_type)
    }

    pub fn tx_extra_info(&self, tx_len: usize) -> ChainInfo {
        let state = self.last_state.as_ref().expect("the app state is expected");
        let min_fee = state
            .top_level
            .network_params
            .calculate_fee(tx_len)
            .expect("invalid fee policy");
        ChainInfo {
            min_fee_computed: min_fee,
            chain_hex_id: self.chain_hex_id,
            block_time: state.block_time,
            block_height: state.block_height,
            max_evidence_age: state.max_evidence_age,
        }
    }

    /// Double check the circulating coins
    ///
    /// - utxo_coins = withdraw - deposit - transfer tx fee
    /// - utxo_coins + staking + reward_pool = init_dist + minted
    /// - init_dist = Coin::max() - expansion_cap  -- checked at init chain
    pub fn check_circulating_coins(&self) -> Coin {
        let state = self.last_state.as_ref().expect("expect last_state");
        let staking = sum_staking_coins(
            &kv_getter!(self, BufferType::Consensus),
            state.staking_version,
        )
        .unwrap();
        let total1 = ((state.utxo_coins + staking).unwrap()
            + state.top_level.rewards_pool.period_bonus)
            .unwrap();

        let init_dist = (Coin::max()
            - state
                .top_level
                .network_params
                .get_rewards_monetary_expansion_cap())
        .unwrap();
        let total2 = (init_dist + state.top_level.rewards_pool.minted).unwrap();

        assert_eq!(total1, total2);
        total1
    }
}
