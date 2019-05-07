use abci::*;
use bincode::{deserialize, serialize};
use bit_vec::BitVec;
use chain_core::common::merkle::MerkleTree;
use chain_core::common::Timespec;
use chain_core::common::{H256, HASH_SIZE_256};
use chain_core::compute_app_hash;
use chain_core::init::config::InitConfig;
use chain_core::state::{BlockHeight, RewardsPoolState};
use chain_core::tx::{
    data::{attribute::TxAttributes, Tx, TxId},
    fee::LinearFee,
    TxAux,
};
use hex::decode;
use log::{info, warn};
use protobuf::Message;
use rlp::{Encodable, RlpStream};
use serde::{Deserialize, Serialize};

use crate::storage::*;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ChainNodeState {
    /// last processed block height
    pub last_block_height: BlockHeight,
    /// last committed merkle root
    pub last_apphash: H256,
    /// time in previous block's header or genesis time
    pub block_time: Timespec,
    /// last rewards pool state
    pub rewards_pool: RewardsPoolState,
    /// fee policy to apply
    pub fee_policy: LinearFee,
}

/// The global ABCI state
pub struct ChainNodeApp {
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
}

impl ChainNodeApp {
    /// Creates a new App initialized with a given storage (could be in-mem or persistent).
    /// If persistent storage is used, it'll try to recove stored arguments (e.g. last app hash / block height) from it.
    ///
    /// # Arguments
    ///
    /// * `gah` - hex-encoded genesis app hash
    /// * `chain_id` - the chain ID set in Tendermint genesis.json (our name convention is that the last two characters should be hex digits)
    /// * `storage` - underlying storage to be used (in-mem or persistent)
    pub fn new_with_storage(gah: &str, chain_id: &str, storage: Storage) -> Self {
        let decoded_gah = decode(gah).expect("failed to decode genesis app hash");
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
            let stored_gah = storage
                .db
                .get(COL_NODE_INFO, GENESIS_APP_HASH_KEY)
                .expect("genesis hash lookup")
                .expect("last app state found, but genesis app hash not stored");
            let mut stored_genesis = [0u8; HASH_SIZE_256];
            stored_genesis.copy_from_slice(&stored_gah[..]);

            if stored_genesis != genesis_app_hash {
                panic!("stored genesis app hash: {:?} does not match the provided genesis app hash: {:?}", stored_genesis, genesis_app_hash);
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
            let last_state: Option<ChainNodeState> =
                Some(deserialize(&last_app_state[..]).expect("deserialize app state"));
            ChainNodeApp {
                storage,
                delivered_txs: Vec::new(),
                chain_hex_id,
                genesis_app_hash: genesis_app_hash.into(),
                last_state,
            }
        } else {
            info!("no last app state stored");
            let mut inittx = storage.db.transaction();
            inittx.put(COL_NODE_INFO, GENESIS_APP_HASH_KEY, &genesis_app_hash);
            inittx.put(COL_EXTRA, CHAIN_ID_KEY, chain_id.as_bytes());
            storage
                .db
                .write(inittx)
                .expect("genesis app hash should be stored");
            ChainNodeApp {
                storage,
                delivered_txs: Vec::new(),
                chain_hex_id,
                genesis_app_hash: genesis_app_hash.into(),
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
    /// * `storage_config` - configuration for storage (currently only the path, but TODO: more options, e.g. SSD or HDD params)
    pub fn new(gah: &str, chain_id: &str, storage_config: &StorageConfig<'_>) -> ChainNodeApp {
        ChainNodeApp::new_with_storage(gah, chain_id, Storage::new(storage_config))
    }

    /// Handles InitChain requests:
    /// should validate initial genesis distribution, initialize everything in the key-value DB and check it matches the expected values
    /// provided as arguments.
    pub fn init_chain_handler(&mut self, _req: &RequestInitChain) -> ResponseInitChain {
        let db = &self.storage.db;
        let conf: InitConfig =
            serde_json::from_slice(&_req.app_state_bytes).expect("failed to parse initial config");
        let dist_result = conf.validate_distribution();
        if dist_result.is_ok() {
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
            let utxos = conf.generate_utxos(&TxAttributes::new(self.chain_hex_id));
            let ids: Vec<TxId> = utxos.iter().map(Tx::id).collect();
            let tree = MerkleTree::new(&ids);
            let rp = conf.get_genesis_rewards_pool();

            let genesis_app_hash = compute_app_hash(&tree, &rp);
            if self.genesis_app_hash != genesis_app_hash {
                panic!("initchain resulting genesis app hash: {:?} does not match the expected genesis app hash: {:?}", genesis_app_hash, self.genesis_app_hash);
            }

            let mut inittx = db.transaction();
            // TODO: check consensus parameters
            match _req.consensus_params.as_ref() {
                Some(cp) => {
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

            // TODO: checking validators
            let validators: Vec<Vec<u8>> = _req
                .validators
                .iter()
                .map(|x| {
                    (x as &dyn Message)
                        .write_to_bytes()
                        .expect("genesis validators")
                })
                .collect();
            let mut rlp = RlpStream::new();
            rlp.begin_list(validators.len());
            for v in validators.iter() {
                rlp.append_list(v);
            }
            inittx.put(COL_EXTRA, b"init_chain_validators", &rlp.out());

            for utxo in utxos.iter() {
                let txid = utxo.id();
                info!("creating genesis tx (id: {:?})", &txid);
                inittx.put(COL_BODIES, &txid.as_bytes(), &utxo.rlp_bytes());
                inittx.put(
                    COL_TX_META,
                    &txid.as_bytes(),
                    &BitVec::from_elem(1, false).to_bytes(),
                );
            }

            let last_state = match _req.time.as_ref() {
                Some(time) => {
                    inittx.put(
                        COL_EXTRA,
                        b"init_chain_time",
                        &(time as &dyn Message).write_to_bytes().expect("time"),
                    );
                    ChainNodeState {
                        last_block_height: 0.into(),
                        last_apphash: genesis_app_hash,
                        block_time: time.get_seconds().into(),
                        rewards_pool: rp,
                        fee_policy: conf.initial_fee_policy,
                    }
                }
                None => {
                    warn!("time not in the initchain request");
                    ChainNodeState {
                        last_block_height: 0.into(),
                        last_apphash: genesis_app_hash,
                        block_time: 0.into(),
                        rewards_pool: rp,
                        fee_policy: conf.initial_fee_policy,
                    }
                }
            };
            inittx.put(
                COL_NODE_INFO,
                LAST_STATE_KEY,
                &serialize(&last_state).expect("serialize state"),
            );

            inittx.put(
                COL_MERKLE_PROOFS,
                &genesis_app_hash.as_bytes(),
                &tree.rlp_bytes(),
            );

            let wr = db.write(inittx);
            if wr.is_err() {
                panic!("db write error: {}", wr.err().unwrap());
            } else {
                self.last_state = Some(last_state);
            }
        } else {
            panic!(
                "distribution validation error: {}",
                dist_result.err().unwrap()
            );
        }
        ResponseInitChain::new()
    }
}
