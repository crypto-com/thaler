mod validator_state;
pub mod validator_state_update;

use std::collections::BTreeMap;
use std::convert::TryInto;

use abci::*;
use enclave_protocol::{EnclaveRequest, EnclaveResponse};
use log::{info, warn};
use parity_scale_codec::{Decode, Encode};
use protobuf::Message;
use serde::{Deserialize, Serialize};

use crate::enclave_bridge::EnclaveProxy;
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
use chain_core::state::tendermint::TendermintValidatorAddress;
use chain_core::state::tendermint::{BlockHeight, TendermintVotePower};
use chain_core::state::{ChainState, RewardsPoolState};
use chain_core::tx::TxAux;
use chain_storage::account::AccountWrapper;
use chain_storage::account::StarlingFixedKey;
use chain_storage::account::{pure_account_storage, AccountStorage};
use chain_storage::{Storage, StorageConfig, StoredChainState};
use chain_tx_validation::NodeChecker;
pub use validator_state::ValidatorState;
use validator_state::ValidatorStateHelper;

/// ABCI app state snapshot
#[derive(Serialize, Deserialize, Clone, Encode, Decode)]
pub struct ChainNodeState {
    /// last processed block height
    pub last_block_height: BlockHeight,
    /// last committed merkle root
    pub last_apphash: H256,
    /// time in previous block's header or genesis time
    pub block_time: Timespec,
    /// state of validators (keys, voting power, punishments, rewards...)
    #[serde(skip)]
    pub validators: ValidatorState,
    /// genesis time
    pub genesis_time: Timespec,

    /// The parts of states which involved in computing app_hash
    pub top_level: ChainState,
}

impl NodeChecker for &ChainNodeState {
    /// minimal required stake
    fn minimum_effective_stake(&self) -> Coin {
        // FIXME: minimal effective
        self.top_level
            .network_params
            .get_required_council_node_stake()
    }
    /// if the TM pubkey/address is already used in the consensus
    fn is_current_validator(&self, address: &TendermintValidatorAddress) -> bool {
        self.validators.is_current_validator(address)
    }
    /// if the TM pubkey/address is already used in the consensus
    fn is_current_validator_stake(&self, address: &StakedStateAddress) -> bool {
        self.validators
            .validator_state_helper
            .validator_voting_power
            .contains_key(address)
    }
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
}

impl ChainNodeState {
    pub fn genesis(
        genesis_apphash: H256,
        genesis_time: Timespec,
        account_root: StarlingFixedKey,
        rewards_pool: RewardsPoolState,
        network_params: NetworkParameters,
        validators: ValidatorState,
    ) -> Self {
        ChainNodeState {
            last_block_height: 0,
            last_apphash: genesis_apphash,
            block_time: genesis_time,
            validators,
            genesis_time,
            top_level: ChainState {
                account_root,
                rewards_pool,
                network_params,
            },
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

fn check_and_store_consensus_params(
    init_consensus_params: Option<&ConsensusParams>,
    _validators: &[(StakedStateAddress, CouncilNode)],
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

fn get_voting_power(
    distribution: &BTreeMap<RedeemAddress, (StakedStateDestination, Coin)>,
    node_address: &StakedStateAddress,
) -> TendermintVotePower {
    match node_address {
        StakedStateAddress::BasicRedeem(a) => TendermintVotePower::from(distribution[a].1),
    }
}

pub fn compute_accounts_root(
    account_storage: &mut AccountStorage,
    accounts: &[StakedState],
) -> H256 {
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
        mut last_app_state: ChainNodeState,
        genesis_app_hash: [u8; HASH_SIZE_256],
        chain_id: &str,
        storage: Storage,
        accounts: AccountStorage,
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
        last_app_state.validators.validator_state_helper =
            ValidatorStateHelper::restore(&accounts, &last_app_state);
        ChainNodeApp {
            storage,
            accounts,
            delivered_txs: Vec::new(),
            uncommitted_account_root_hash: last_app_state.top_level.account_root,
            chain_hex_id,
            genesis_app_hash,
            last_state: Some(last_app_state),
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
        mut storage: Storage,
        accounts: AccountStorage,
        tx_query_address: Option<String>,
    ) -> Self {
        let decoded_gah = hex::decode(gah).expect("failed to decode genesis app hash");
        let mut genesis_app_hash = [0u8; HASH_SIZE_256];
        genesis_app_hash.copy_from_slice(&decoded_gah[..]);
        let chain_hex_id = hex::decode(&chain_id[chain_id.len() - 2..])
            .expect("failed to decode two last hex digits in chain ID")[0];

        if let Some(data) = storage.get_last_app_state() {
            info!("last app state stored");
            let last_state =
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
            storage.write_genesis_chain_id(&genesis_app_hash, chain_id);
            ChainNodeApp {
                storage,
                accounts,
                delivered_txs: Vec::new(),
                uncommitted_account_root_hash: [0u8; 32],
                chain_hex_id,
                genesis_app_hash,
                last_state: None,
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

        let stored_chain_id = self.storage.get_stored_chain_id();
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

        check_and_store_consensus_params(
            req.consensus_params.as_ref(),
            &nodes,
            &network_params,
            &mut self.storage,
        );

        let mut validators = Vec::with_capacity(nodes.len());
        let mut validator_state = ValidatorState::default();
        for (address, node) in nodes.iter() {
            let mut validator = ValidatorUpdate::default();
            let power = get_voting_power(&conf.distribution, address);
            validator.set_power(power.into());
            let pk = get_validator_key(&node);
            validator.set_pub_key(pk);
            validators.push(validator);
            validator_state.add_initial_validator(
                *address,
                power,
                node.clone(),
                network_params.get_block_signing_window(),
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
            validator_state,
        );
        self.storage
            .store_genesis_state(&genesis_state, self.tx_query_address.is_some());

        let wr = self.storage.persist_write();
        if let Err(e) = wr {
            panic!("db write error: {}", e);
        } else {
            self.uncommitted_account_root_hash = genesis_state.top_level.account_root;
            self.last_state = Some(genesis_state);
        }

        ResponseInitChain::new()
    }
}
