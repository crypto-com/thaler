use crate::storage::account::AccountStorage;
use crate::storage::account::AccountWrapper;
use crate::storage::tx::StarlingFixedKey;
use crate::storage::*;
use abci::*;
use chain_core::common::MerkleTree;
use chain_core::common::Timespec;
use chain_core::common::{H256, HASH_SIZE_256};
use chain_core::compute_app_hash;
use chain_core::init::coin::Coin;
use chain_core::init::config::InitConfig;
use chain_core::init::config::InitNetworkParameters;
use chain_core::state::account::Account;
use chain_core::state::CouncilNode;
use chain_core::state::{BlockHeight, RewardsPoolState};
use chain_core::tx::{fee::LinearFee, TxAux};
use kvdb::DBTransaction;
use log::{info, warn};
use parity_codec::{Decode, Encode};
use protobuf::{Message, RepeatedField};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

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
    /// fee policy to apply -- TODO: change to be against T: FeeAlgorithm
    pub fee_policy: LinearFee,
    /// time when unbonded stake can be withdrawn
    pub unbonding_period: u32,
    /// (minimal?) amount required to be bonded in validator-associated accounts
    pub required_council_node_stake: Coin,
    /// council nodes metadata
    pub council_nodes: Vec<CouncilNode>,
}

/// The global ABCI state
pub struct ChainNodeApp {
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
}

impl ChainNodeApp {
    fn restore_from_storage(
        last_app_state: ChainNodeState,
        genesis_app_hash: [u8; HASH_SIZE_256],
        chain_id: &str,
        storage: Storage,
        accounts: AccountStorage,
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
                "stored genesis app hash: {:?} does not match the provided genesis app hash: {:?}",
                stored_genesis, genesis_app_hash
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
        ChainNodeApp {
            storage,
            accounts,
            delivered_txs: Vec::new(),
            uncommitted_account_root_hash: last_app_state.last_account_root_hash,
            chain_hex_id,
            genesis_app_hash,
            last_state: Some(last_app_state),
        }
    }

    /// Creates a new App initialized with a given storage (could be in-mem or persistent).
    /// If persistent storage is used, it'll try to recove stored arguments (e.g. last app hash / block height) from it.
    ///
    /// # Arguments
    ///
    /// * `gah` - hex-encoded genesis app hash
    /// * `chain_id` - the chain ID set in Tendermint genesis.json (our name convention is that the last two characters should be hex digits)
    /// * `storage` - underlying storage to be used (in-mem or persistent)
    /// * `accounts` - underlying storage for account tries to be used (in-mem or persistent)    
    pub fn new_with_storage(
        gah: &str,
        chain_id: &str,
        storage: Storage,
        accounts: AccountStorage,
    ) -> Self {
        let decoded_gah = hex::decode(gah).expect("failed to decode genesis app hash");
        let mut genesis_app_hash = [0u8; HASH_SIZE_256];
        genesis_app_hash.copy_from_slice(&decoded_gah[..]);

        if let Some(last_app_state) = storage
            .db
            .get(COL_NODE_INFO, LAST_STATE_KEY)
            .expect("app state lookup")
        {
            info!("last app state stored");
            let data = last_app_state.to_vec();
            let last_state =
                ChainNodeState::decode(&mut data.as_slice()).expect("deserialize app state");
            ChainNodeApp::restore_from_storage(
                last_state,
                genesis_app_hash,
                chain_id,
                storage,
                accounts,
            )
        } else {
            info!("no last app state stored");
            let chain_hex_id = hex::decode(&chain_id[chain_id.len() - 2..])
                .expect("failed to decode two last hex digits in chain ID")[0];
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
            }
        }
    }

    /// Creates a new App initialized according to a provided storage config (most likely persistent).
    ///
    /// # Arguments
    ///
    /// * `gah` - hex-encoded genesis app hash
    /// * `chain_id` - the chain ID set in Tendermint genesis.json (our name convention is that the last two characters should be hex digits)
    /// * `node_storage_config` - configuration for node storage (currently only the path, but TODO: more options, e.g. SSD or HDD params)
    /// * `account_storage_config` - configuration for account storage
    pub fn new(
        gah: &str,
        chain_id: &str,
        node_storage_config: &StorageConfig<'_>,
        account_storage_config: &StorageConfig<'_>,
    ) -> ChainNodeApp {
        ChainNodeApp::new_with_storage(
            gah,
            chain_id,
            Storage::new(node_storage_config),
            AccountStorage::new(Storage::new(account_storage_config), 20).expect("account db"),
        )
    }

    fn check_and_store_consensus_params(
        init_consensus_params: Option<&ConsensusParams>,
        _validators: &[CouncilNode],
        _network_params: &InitNetworkParameters,
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

    fn store_valid_genesis_state(
        genesis_time: Timespec,
        genesis_app_hash: H256,
        rewards_pool: RewardsPoolState,
        network_params: InitNetworkParameters,
        last_account_root_hash: StarlingFixedKey,
        council_nodes: Vec<CouncilNode>,
        inittx: &mut DBTransaction,
    ) -> ChainNodeState {
        let last_state = ChainNodeState {
            last_block_height: 0,
            last_apphash: genesis_app_hash,
            block_time: genesis_time,
            last_account_root_hash,
            rewards_pool,
            fee_policy: network_params.initial_fee_policy,
            unbonding_period: network_params.unbonding_period,
            required_council_node_stake: network_params.required_council_node_stake,
            council_nodes,
        };
        let encoded = last_state.encode();
        inittx.put(COL_NODE_INFO, LAST_STATE_KEY, &encoded);
        inittx.put(COL_EXTRA, b"init_chain_state", &encoded);
        last_state
    }

    /// Handles InitChain requests:
    /// should validate initial genesis distribution, initialize everything in the key-value DB and check it matches the expected values
    /// provided as arguments.
    pub fn init_chain_handler(&mut self, _req: &RequestInitChain) -> ResponseInitChain {
        let db = &self.storage.db;
        let genesis_time = _req.time.as_ref().expect("genesis time").get_seconds();
        let conf: InitConfig =
            serde_json::from_slice(&_req.app_state_bytes).expect("failed to parse initial config");
        let dist_result = conf.validate_config_get_genesis(genesis_time);
        if let Ok((accounts, rp, nodes)) = dist_result {
            let stored_chain_id = db
                .get(COL_EXTRA, CHAIN_ID_KEY)
                .unwrap()
                .expect("last app hash found, no but chain id stored");
            if stored_chain_id != _req.chain_id.as_bytes() {
                panic!(
                    "stored chain id: {:?} does not match the provided chain id: {:?}",
                    stored_chain_id, _req.chain_id
                );
            }

            let tx_tree = MerkleTree::empty();

            let keys: Vec<StarlingFixedKey> = accounts.iter().map(Account::key).collect();
            // TODO: get rid of the extra allocations
            let wrapped: Vec<AccountWrapper> =
                accounts.iter().map(|x| AccountWrapper(x.clone())).collect();
            let new_account_root = self
                .accounts
                .insert(
                    None,
                    &mut keys.iter().collect::<Vec<_>>(),
                    &mut wrapped.iter().collect::<Vec<_>>(),
                )
                .expect("initial insert");

            let genesis_app_hash = compute_app_hash(&tx_tree, &new_account_root, &rp);
            if self.genesis_app_hash != genesis_app_hash {
                panic!("initchain resulting genesis app hash: {:?} does not match the expected genesis app hash: {:?}", genesis_app_hash, self.genesis_app_hash);
            }

            let mut inittx = db.transaction();
            ChainNodeApp::check_and_store_consensus_params(
                _req.consensus_params.as_ref(),
                &nodes,
                &conf.network_params,
                &mut inittx,
            );
            // NOTE: &_req.validators are ignored / replaced by init config
            let mut validators = Vec::with_capacity(nodes.len());
            // TODO: check not empty here or in initconfig validation?
            for node in nodes.iter() {
                let mut validator = ValidatorUpdate::default();
                // TODO: validator power in coins rather than base units (i.e. divide by 1_0000_0000?)
                validator.set_power(
                    conf.distribution[&node.staking_account_address]
                        .0
                        .try_into()
                        .expect("initial validator power exceeds i64"),
                );
                let mut pk = PubKey::new();
                let (keytype, key) = node.consensus_pubkey.to_validator_update();
                pk.set_field_type(keytype);
                pk.set_data(key);
                validator.set_pub_key(pk);
                validators.push(validator);
            }
            let mut resp = ResponseInitChain::new();
            resp.set_validators(RepeatedField::from(validators));
            let last_state = ChainNodeApp::store_valid_genesis_state(
                genesis_time,
                genesis_app_hash,
                rp,
                conf.network_params,
                new_account_root,
                nodes,
                &mut inittx,
            );

            let wr = db.write(inittx);
            if wr.is_err() {
                panic!("db write error: {}", wr.err().unwrap());
            } else {
                self.uncommitted_account_root_hash = last_state.last_account_root_hash;
                self.last_state = Some(last_state);
            }

            resp
        } else {
            panic!(
                "distribution validation error: {}",
                dist_result.err().unwrap()
            );
        }
    }
}
