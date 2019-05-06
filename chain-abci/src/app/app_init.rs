use abci::*;
use bit_vec::BitVec;
use chain_core::common::merkle::MerkleTree;
use chain_core::common::Timespec;
use chain_core::common::{H256, HASH_SIZE_256};
use chain_core::compute_app_hash;
use chain_core::init::config::InitConfig;
use chain_core::state::{BlockHeight, RewardsPoolState};
use chain_core::tx::{
    data::{attribute::TxAttributes, Tx, TxId},
    TxAux,
};
use hex::decode;
use integer_encoding::VarInt;
use log::info;
use protobuf::Message;
use rlp::{Decodable, Encodable, Rlp, RlpStream};

use crate::storage::*;

/// The global ABCI state
pub struct ChainNodeApp {
    /// the underlying key-value storage (+ possibly some info in the future)
    pub storage: Storage,
    /// last processed block height
    pub last_block_height: BlockHeight,
    /// next block height
    pub uncommitted_block_height: BlockHeight,
    /// valid transactions after DeliverTx before EndBlock/Commit
    pub delivered_txs: Vec<TxAux>,
    /// a reference to genesis (used when there is no committed state)
    pub genesis_app_hash: H256,
    /// last committed merkle root (if any)
    pub last_apphash: Option<H256>,
    /// last two hex digits in chain_id
    pub chain_hex_id: u8,
    /// time in previous block's header or genesis time
    pub block_time: Option<Timespec>,
    /// last rewards pool state
    pub rewards_pool: Option<RewardsPoolState>,
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

        let last_app_hash = storage.db.get(COL_NODE_INFO, LAST_APP_HASH_KEY).unwrap();

        if last_app_hash.is_none() {
            info!("no last app hash stored");
            let mut inittx = storage.db.transaction();
            inittx.put(COL_NODE_INFO, GENESIS_APP_HASH_KEY, &genesis_app_hash);

            inittx.put(COL_EXTRA, CHAIN_ID_KEY, chain_id.as_bytes());
            storage
                .db
                .write(inittx)
                .expect("genesis app hash should be stored");
            ChainNodeApp {
                storage,
                last_block_height: 0.into(),
                uncommitted_block_height: 0.into(),
                delivered_txs: Vec::new(),
                last_apphash: None,
                chain_hex_id,
                genesis_app_hash: genesis_app_hash.into(),
                block_time: None,
                rewards_pool: None,
            }
        } else {
            info!("last app hash stored");
            let stored_gah = storage
                .db
                .get(COL_NODE_INFO, GENESIS_APP_HASH_KEY)
                .unwrap()
                .expect("last app hash found, but genesis app hash not stored");
            let mut stored_genesis = [0u8; HASH_SIZE_256];
            stored_genesis.copy_from_slice(&stored_gah[..]);

            if stored_genesis != genesis_app_hash {
                panic!("stored genesis app hash: {:?} does not match the provided genesis app hash: {:?}", stored_genesis, genesis_app_hash);
            }
            let stored_chain_id = storage
                .db
                .get(COL_EXTRA, CHAIN_ID_KEY)
                .unwrap()
                .expect("last app hash found, but no chain id stored");
            if stored_chain_id != chain_id.as_bytes() {
                panic!(
                    "stored chain id: {:?} does not match the provided chain id: {:?}",
                    stored_chain_id, chain_id
                );
            }
            let last_block_height = i64::decode_var_vec(
                &storage
                    .db
                    .get(COL_NODE_INFO, LAST_BLOCK_HEIGHT_KEY)
                    .expect("last apphash found, but last block height not found")
                    .unwrap()
                    .to_vec(),
            )
            .0;

            let rewards_pool = RewardsPoolState::decode(&Rlp::new(
                &storage
                    .db
                    .get(COL_NODE_INFO, REWARDS_POOL_STATE_KEY)
                    .unwrap()
                    .expect("last app hash found, but no rewards pool state stored"),
            ))
            .expect(
                "failed to decode stored
                rewards pool state",
            );
            let mut app_hash = [0u8; HASH_SIZE_256];
            app_hash.copy_from_slice(&last_app_hash.unwrap()[..]);
            ChainNodeApp {
                storage,
                last_block_height: last_block_height.into(),
                uncommitted_block_height: 0.into(),
                delivered_txs: Vec::new(),
                last_apphash: Some(app_hash.into()),
                chain_hex_id,
                genesis_app_hash: genesis_app_hash.into(),
                block_time: None,
                rewards_pool: Some(rewards_pool),
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
            match _req.time.as_ref() {
                Some(time) => {
                    inittx.put(
                        COL_EXTRA,
                        b"init_chain_time",
                        &(time as &dyn Message).write_to_bytes().expect("time"),
                    );
                }
                None => {
                    info!("time not in the initchain request");
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
            inittx.put(COL_NODE_INFO, REWARDS_POOL_STATE_KEY, &rp.rlp_bytes());
            inittx.put(
                COL_NODE_INFO,
                LAST_APP_HASH_KEY,
                &genesis_app_hash.as_bytes(),
            );
            inittx.put(
                COL_NODE_INFO,
                LAST_BLOCK_HEIGHT_KEY,
                &i64::encode_var_vec(self.last_block_height.into()),
            );
            inittx.put(
                COL_MERKLE_PROOFS,
                &genesis_app_hash.as_bytes(),
                &tree.rlp_bytes(),
            );

            let wr = db.write(inittx);
            if wr.is_err() {
                // TODO: panic?
                println!("db write error: {}", wr.err().unwrap());
            } else {
                self.rewards_pool = Some(rp);
                self.last_apphash = Some(genesis_app_hash);
            }

            self.block_time = Some(_req.time.as_ref().unwrap().seconds.into());
        } else {
            // TODO: panic?
            println!(
                "distribution validation error: {}",
                dist_result.err().unwrap()
            );
        }
        ResponseInitChain::new()
    }
}
