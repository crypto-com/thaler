mod app_init;
mod commit;
mod query;
mod validate_tx;

pub use self::app_init::ChainNodeApp;
use abci::*;
use ethbloom::{Bloom, Input};
use secp256k1::constants::PUBLIC_KEY_SIZE;
use storage::tx::spend_utxos;

impl abci::Application for ChainNodeApp {
    /// Query Connection: Called on startup from Tendermint.  The application should normally
    /// return the last know state so Tendermint can determine if it needs to replay blocks
    /// to the application.
    fn info(&mut self, _req: &RequestInfo) -> ResponseInfo {
        info!("received info request");
        let mut resp = ResponseInfo::new();
        if self.last_apphash.is_some() {
            resp.last_block_app_hash = self.last_apphash.unwrap().to_vec();
            resp.last_block_height = self.last_block_height;
        } else {
            resp.last_block_app_hash = self.genesis_app_hash.to_vec();
        }
        resp
    }

    /// Query Connection: Query your application. This usually resolves through a merkle tree holding
    /// the state of the app.
    fn query(&mut self, _req: &RequestQuery) -> ResponseQuery {
        info!("received query request");
        ChainNodeApp::query_handler(self, _req)
    }

    /// Mempool Connection:  Used to validate incoming transactions.  If the application reponds
    /// with a non-zero value, the transaction is added to Tendermint's mempool for processing
    /// on the deliver_tx call below.
    fn check_tx(&mut self, _req: &RequestCheckTx) -> ResponseCheckTx {
        info!("received checktx request");
        let mut resp = ResponseCheckTx::new();
        ChainNodeApp::validate_tx_req(self, _req, &mut resp);
        resp
    }

    /// Consensus Connection:  Called once on startup. Usually used to establish initial (genesis)
    /// state.
    fn init_chain(&mut self, _req: &RequestInitChain) -> ResponseInitChain {
        info!("received initchain request");
        ChainNodeApp::init_chain_handler(self, _req)
    }

    /// Consensus Connection: Called at the start of processing a block of transactions
    /// The flow is:
    /// begin_block()
    ///   deliver_tx()  for each transaction in the block
    /// end_block()
    /// commit()
    fn begin_block(&mut self, req: &RequestBeginBlock) -> ResponseBeginBlock {
        info!("received beginblock request");
        assert!(
            !self.uncommitted_block,
            "received beginblock request while processing an uncomitted block"
        );
        // TODO: process RequestBeginBlock -- e.g. rewards for validators? + punishment for malicious ByzantineValidators
        self.uncommitted_block = true;
        // TODO: Check security implications once https://github.com/tendermint/tendermint/issues/2653 is closed
        self.block_time = Some(
            req.header
                .as_ref()
                .expect("Begin block request does not have header")
                .time
                .as_ref()
                .expect("Header does not have a timestamp")
                .seconds,
        );
        ResponseBeginBlock::new()
    }

    /// Consensus Connection: Actually processing the transaction, performing some form of a
    /// state transistion.
    fn deliver_tx(&mut self, _req: &RequestDeliverTx) -> ResponseDeliverTx {
        info!("received delivertx request");
        assert!(
            self.uncommitted_block,
            "received deliver_tx request, but haven't received begin_block"
        );
        let mut resp = ResponseDeliverTx::new();
        let mtxaux = ChainNodeApp::validate_tx_req(self, _req, &mut resp);
        if resp.code == 0 && mtxaux.is_some() {
            let txaux = mtxaux.unwrap();
            let txid = txaux.tx.id();
            let mut inittx = self.storage.db.transaction();
            spend_utxos(&txaux, self.storage.db.clone(), &mut inittx);
            self.storage.db.write_buffered(inittx);
            self.delivered_txs.push(txaux);
            let mut kvpair = KVPair::new();
            kvpair.key = Vec::from(&b"txid"[..]);
            // TODO: "Keys and values in tags must be UTF-8 encoded strings" ?
            kvpair.value = Vec::from(&txid[..]);
            resp.tags.push(kvpair);
        }
        resp
    }

    /// Consensus Connection: Called at the end of the block.  Often used to update the validator set.
    fn end_block(&mut self, _req: &RequestEndBlock) -> ResponseEndBlock {
        info!("received endblock request");
        assert!(
            self.uncommitted_block,
            "received end_block request, but haven't received begin_block"
        );
        let mut resp = ResponseEndBlock::new();
        let mut keys = self
            .delivered_txs
            .iter()
            .flat_map(|x| x.tx.attributes.allowed_view.iter().map(|x| x.view_key.1))
            .peekable();
        if keys.peek().is_some() {
            // TODO: explore alternatives, e.g. https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
            let mut bloom = Bloom::default();
            for key in keys {
                let k: &[u8; PUBLIC_KEY_SIZE - 1] = &key;
                bloom.accrue(Input::Raw(k));
            }
            let mut kvpair = KVPair::new();
            kvpair.key = Vec::from(&b"ethbloom"[..]);
            // TODO: "Keys and values in tags must be UTF-8 encoded strings" ?
            kvpair.value = Vec::from(&bloom.data()[..]);
            resp.tags.push(kvpair);
        }
        // TODO: skipchain-based validator changes?
        self.uncommitted_block_height = _req.height;
        resp
    }

    /// Consensus Connection: Commit the block with the latest state from the application.
    fn commit(&mut self, _req: &RequestCommit) -> ResponseCommit {
        info!("received commit request");
        assert!(
            self.uncommitted_block,
            "received commit request, but haven't received begin_block"
        );
        ChainNodeApp::commit_handler(self, _req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abci::Application;
    use bit_vec::BitVec;
    use chain_core::common::{merkle::MerkleTree, HASH_SIZE_256};
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::init::config::{ERC20Owner, InitConfig};
    use chain_core::tx::{
        data::{
            access::{TxAccess, TxAccessPolicy},
            address::ExtendedAddr,
            attribute::TxAttributes,
            input::TxoPointer,
            output::TxOut,
            txid_hash, Tx, TxId,
        },
        witness::{tree::pk_to_raw, TxInWitness, TxWitness},
        TxAux,
    };
    use ethbloom::{Bloom, Input};
    use hex::decode;
    use kvdb::KeyValueDB;
    use kvdb_memorydb::create;
    use secp256k1::{key::PublicKey, key::SecretKey, Secp256k1};
    use serde_cbor::{from_slice, ser::to_vec_packed};
    use std::sync::Arc;
    use storage::tx::tests::get_tx_witness;
    use storage::*;

    fn create_db() -> Arc<KeyValueDB> {
        Arc::new(create(NUM_COLUMNS.unwrap()))
    }

    const TEST_CHAIN_ID: &str = "test-00";

    #[test]
    fn proper_hash_and_chainid_should_be_stored() {
        let db = create_db();
        let example_hash = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10962";
        let _app = ChainNodeApp::new_with_storage(
            example_hash,
            TEST_CHAIN_ID,
            Storage::new_db(db.clone()),
        );
        let decoded_gah = decode(example_hash).unwrap();
        let stored_gah = db
            .get(COL_NODE_INFO, GENESIS_APP_HASH_KEY)
            .unwrap()
            .unwrap();
        let mut stored_genesis = [0u8; HASH_SIZE_256];
        stored_genesis.copy_from_slice(&stored_gah[..]);
        assert_eq!(decoded_gah, stored_genesis);
        let chain_id = db.get(COL_EXTRA, CHAIN_ID_KEY).unwrap().unwrap();
        assert_eq!(chain_id, TEST_CHAIN_ID.as_bytes());
    }

    #[test]
    #[should_panic]
    fn too_long_hash_should_panic() {
        let db = create_db();
        let example_hash = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10962F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10962";
        let _app = ChainNodeApp::new_with_storage(
            example_hash,
            TEST_CHAIN_ID,
            Storage::new_db(db.clone()),
        );
    }

    #[test]
    #[should_panic]
    fn chain_id_without_hex_digits_should_panic() {
        let db = create_db();
        let example_hash = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10962";
        let _app =
            ChainNodeApp::new_with_storage(example_hash, "test", Storage::new_db(db.clone()));
    }

    #[test]
    #[should_panic]
    fn nonhex_hash_should_panic() {
        let db = create_db();
        let example_hash = "EOWNEOIWFNOPXZ./32";
        let _app = ChainNodeApp::new_with_storage(
            example_hash,
            TEST_CHAIN_ID,
            Storage::new_db(db.clone()),
        );
    }

    #[test]
    #[should_panic]
    fn previously_stored_hash_should_match() {
        let db = create_db();
        let example_hash = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10962";
        let decoded_gah = decode(example_hash).unwrap();
        let mut genesis_app_hash = [0u8; HASH_SIZE_256];
        genesis_app_hash.copy_from_slice(&decoded_gah[..]);
        let mut inittx = db.transaction();
        inittx.put(COL_NODE_INFO, GENESIS_APP_HASH_KEY, &genesis_app_hash);
        inittx.put(COL_NODE_INFO, LAST_APP_HASH_KEY, &genesis_app_hash);
        db.write(inittx).unwrap();
        let example_hash2 = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10963";
        let _app = ChainNodeApp::new_with_storage(
            example_hash2,
            TEST_CHAIN_ID,
            Storage::new_db(db.clone()),
        );
    }

    fn init_chain_for(address: RedeemAddress) -> ChainNodeApp {
        let db = create_db();
        let c = InitConfig::new(vec![ERC20Owner::new(address, Coin::max())]);
        let utxos = c.generate_utxos(&TxAttributes::new(0));
        let txids: Vec<TxId> = utxos.iter().map(|x| x.id()).collect();
        let tree = MerkleTree::new(&txids);
        let genesis_app_hash = tree.get_root_hash();
        let example_hash = hex::encode_upper(genesis_app_hash);
        let mut app = ChainNodeApp::new_with_storage(
            &example_hash,
            TEST_CHAIN_ID,
            Storage::new_db(db.clone()),
        );
        let mut req = RequestInitChain::default();
        req.set_time(::protobuf::well_known_types::Timestamp::new());
        req.set_app_state_bytes(serde_json::to_vec(&c).unwrap());
        req.set_chain_id(String::from(TEST_CHAIN_ID));
        app.init_chain(&req);
        return app;
    }

    #[test]
    fn init_chain_should_create_db_items() {
        let app = init_chain_for(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse()
                .unwrap(),
        );
        let genesis_app_hash = app.genesis_app_hash;
        let db = app.storage.db;
        let gah = db.get(COL_NODE_INFO, LAST_APP_HASH_KEY).unwrap().unwrap();
        let mut stored_genesis = [0u8; HASH_SIZE_256];
        stored_genesis.copy_from_slice(&gah[..]);
        assert_eq!(genesis_app_hash, stored_genesis);
        assert_eq!(1, db.iter(COL_TX_META).count());
        assert_eq!(1, db.iter(COL_BODIES).count());
        assert!(db.get(COL_MERKLE_PROOFS, &stored_genesis[..]).is_ok());
        assert!(db.get(COL_NODE_INFO, LAST_BLOCK_HEIGHT_KEY).is_ok());
    }

    #[test]
    #[should_panic]
    fn init_chain_panics_with_different_app_hash() {
        let db = create_db();
        let c = InitConfig::new(vec![ERC20Owner::new(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse()
                .unwrap(),
            Coin::max(),
        )]);
        let example_hash = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10963";
        let mut app = ChainNodeApp::new_with_storage(
            &example_hash,
            TEST_CHAIN_ID,
            Storage::new_db(db.clone()),
        );
        let mut req = RequestInitChain::default();
        req.set_app_state_bytes(serde_json::to_vec(&c).unwrap());
        app.init_chain(&req);
    }

    #[test]
    #[should_panic]
    fn init_chain_panics_with_empty_app_bytes() {
        let db = create_db();
        let example_hash = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10963";
        let mut app = ChainNodeApp::new_with_storage(
            &example_hash,
            TEST_CHAIN_ID,
            Storage::new_db(db.clone()),
        );
        let req = RequestInitChain::default();
        app.init_chain(&req);
    }

    #[test]
    fn check_tx_should_reject_empty_tx() {
        let mut app = init_chain_for(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse()
                .unwrap(),
        );
        let creq = RequestCheckTx::default();
        let cresp = app.check_tx(&creq);
        assert_ne!(0, cresp.code);
    }

    #[test]
    fn check_tx_should_reject_invalid_tx() {
        let mut app = init_chain_for(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse()
                .unwrap(),
        );
        let mut creq = RequestCheckTx::default();
        let tx = TxAux::new(Tx::new(), TxWitness::new());
        creq.set_tx(serde_cbor::ser::to_vec_packed(&tx).unwrap());
        let cresp = app.check_tx(&creq);
        assert_ne!(0, cresp.code);
    }

    fn prepare_app_valid_tx() -> (ChainNodeApp, TxAux) {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let addr = RedeemAddress::from(&public_key);
        let app = init_chain_for(addr);
        let old_tx: Tx =
            serde_cbor::from_slice(&app.storage.db.iter(COL_BODIES).next().unwrap().1).unwrap();
        let old_tx_id = old_tx.id();
        let old_utxos_before = BitVec::from_bytes(
            &app.storage
                .db
                .get(COL_TX_META, &old_tx_id)
                .unwrap()
                .unwrap(),
        );
        assert!(!old_utxos_before.any());

        let txp = TxoPointer::new(old_tx_id, 0);
        let mut tx = Tx::new();
        tx.attributes.allowed_view.push(TxAccessPolicy::new(
            pk_to_raw(public_key),
            TxAccess::AllData,
        ));
        let eaddr = ExtendedAddr::BasicRedeem(addr.0);
        tx.add_input(txp);
        tx.add_output(TxOut::new(eaddr, (Coin::max() - Coin::unit()).unwrap()));
        tx.add_output(TxOut::new(
            ExtendedAddr::BasicRedeem(RedeemAddress::default().0),
            Coin::unit(),
        ));
        let witness: Vec<TxInWitness> = vec![get_tx_witness(secp, &tx, &secret_key)];
        let txaux = TxAux::new(tx, witness.into());
        (app, txaux)
    }

    #[test]
    fn check_tx_should_accept_valid_tx() {
        let (mut app, txaux) = prepare_app_valid_tx();
        let mut creq = RequestCheckTx::default();
        creq.set_tx(serde_cbor::ser::to_vec_packed(&txaux).unwrap());
        let cresp = app.check_tx(&creq);
        assert_eq!(0, cresp.code);
    }

    #[test]
    #[should_panic]
    fn two_beginblocks_should_panic() {
        let mut app = init_chain_for(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse()
                .unwrap(),
        );
        let bbreq = RequestBeginBlock::default();
        app.begin_block(&bbreq);
        app.begin_block(&bbreq);
    }

    fn begin_block(app: &mut ChainNodeApp) {
        let mut bbreq = RequestBeginBlock::default();
        let mut header = Header::default();
        header.set_time(::protobuf::well_known_types::Timestamp::new());
        bbreq.set_header(header);
        app.begin_block(&bbreq);
    }

    #[test]
    fn beginblocks_should_set_uncommitted_flag() {
        let mut app = init_chain_for(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse()
                .unwrap(),
        );
        assert!(!app.uncommitted_block);
        begin_block(&mut app);
        assert!(app.uncommitted_block);
    }

    #[test]
    fn deliver_tx_should_reject_empty_tx() {
        let mut app = init_chain_for(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse()
                .unwrap(),
        );
        assert_eq!(0, app.delivered_txs.len());
        begin_block(&mut app);
        let creq = RequestDeliverTx::default();
        let cresp = app.deliver_tx(&creq);
        assert_ne!(0, cresp.code);
        assert_eq!(0, app.delivered_txs.len());
        assert_eq!(0, cresp.tags.len());
    }

    #[test]
    fn deliver_tx_should_reject_invalid_tx() {
        let mut app = init_chain_for(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse()
                .unwrap(),
        );
        assert_eq!(0, app.delivered_txs.len());
        begin_block(&mut app);
        let mut creq = RequestDeliverTx::default();
        let tx = TxAux::new(Tx::new(), TxWitness::new());
        creq.set_tx(serde_cbor::ser::to_vec_packed(&tx).unwrap());
        let cresp = app.deliver_tx(&creq);
        assert_ne!(0, cresp.code);
        assert_eq!(0, app.delivered_txs.len());
        assert_eq!(0, cresp.tags.len());
    }

    fn deliver_valid_tx() -> (ChainNodeApp, TxAux, ResponseDeliverTx) {
        let (mut app, txaux) = prepare_app_valid_tx();
        assert_eq!(0, app.delivered_txs.len());
        begin_block(&mut app);
        let mut creq = RequestDeliverTx::default();
        creq.set_tx(serde_cbor::ser::to_vec_packed(&txaux).unwrap());
        let cresp = app.deliver_tx(&creq);
        (app, txaux, cresp)
    }

    #[test]
    fn deliver_tx_should_add_valid_tx() {
        let (app, txaux, cresp) = deliver_valid_tx();
        assert_eq!(0, cresp.code);
        assert_eq!(1, app.delivered_txs.len());
        assert_eq!(1, cresp.tags.len());
        let txid = txaux.tx.id();
        assert_eq!(&txid[..], &cresp.tags[0].value[..]);
    }

    #[test]
    #[should_panic]
    fn delivertx_without_beginblocks_should_panic() {
        let mut app = init_chain_for(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse()
                .unwrap(),
        );
        let creq = RequestDeliverTx::default();
        app.deliver_tx(&creq);
    }

    #[test]
    #[should_panic]
    fn endblock_without_beginblocks_should_panic() {
        let mut app = init_chain_for(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse()
                .unwrap(),
        );
        let creq = RequestEndBlock::default();
        let _cresp = app.end_block(&creq);
    }

    #[test]
    fn endblock_should_change_block_height() {
        let mut app = init_chain_for(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse()
                .unwrap(),
        );
        begin_block(&mut app);
        let mut creq = RequestEndBlock::default();
        creq.set_height(10);
        assert_ne!(10, app.uncommitted_block_height);
        let cresp = app.end_block(&creq);
        assert_eq!(10, app.uncommitted_block_height);
        assert_eq!(0, cresp.tags.len());
    }

    #[test]
    #[should_panic]
    fn commit_without_beginblocks_should_panic() {
        let mut app = init_chain_for(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse()
                .unwrap(),
        );
        let creq = RequestCommit::default();
        let _cresp = app.commit(&creq);
    }

    #[test]
    fn valid_commit_should_persist() {
        let (mut app, txaux, _) = deliver_valid_tx();
        let old_tx: Tx =
            serde_cbor::from_slice(&app.storage.db.iter(COL_BODIES).next().unwrap().1).unwrap();
        let old_tx_id = old_tx.id();
        let old_app_hash = app.last_apphash;
        let mut endreq = RequestEndBlock::default();
        endreq.set_height(10);
        let cresp = app.end_block(&endreq);
        assert_eq!(1, cresp.tags.len());
        let bloom = Bloom::from(&cresp.tags[0].value[..]);
        assert!(bloom.contains_input(Input::Raw(&txaux.tx.attributes.allowed_view[0].view_key.1)));
        assert!(!bloom.contains_input(Input::Raw(&[0u8; 32][..])));

        assert!(app
            .storage
            .db
            .get(COL_BODIES, &txaux.tx.id())
            .unwrap()
            .is_none());
        assert!(app
            .storage
            .db
            .get(COL_WITNESS, &txaux.tx.id())
            .unwrap()
            .is_none());
        assert_ne!(10, app.last_block_height);
        assert!(app.uncommitted_block);
        let cresp = app.commit(&RequestCommit::default());
        assert!(app
            .storage
            .db
            .get(COL_BODIES, &txaux.tx.id())
            .unwrap()
            .is_some());
        assert!(app
            .storage
            .db
            .get(COL_WITNESS, &txaux.tx.id())
            .unwrap()
            .is_some());
        assert_eq!(10, app.last_block_height);
        assert_ne!(old_app_hash, app.last_apphash);
        assert_eq!(&app.last_apphash.unwrap()[..], &cresp.data[..]);
        assert!(app
            .storage
            .db
            .get(COL_MERKLE_PROOFS, &cresp.data[..])
            .unwrap()
            .is_some());
        assert!(!app.uncommitted_block);
        let old_utxos_after = BitVec::from_bytes(
            &app.storage
                .db
                .get(COL_TX_META, &old_tx_id)
                .unwrap()
                .unwrap(),
        );
        assert!(old_utxos_after.get(0).unwrap());
        let new_utxos = BitVec::from_bytes(
            &app.storage
                .db
                .get(COL_TX_META, &txaux.tx.id())
                .unwrap()
                .unwrap(),
        );
        assert!(!new_utxos.any());
    }

    #[test]
    fn no_delivered_tx_commit_should() {
        let mut app = init_chain_for(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse()
                .unwrap(),
        );
        let old_app_hash = app.genesis_app_hash;
        begin_block(&mut app);
        app.end_block(&RequestEndBlock::default());
        let cresp = app.commit(&RequestCommit::default());
        assert_eq!(old_app_hash, app.last_apphash.unwrap());
        assert_eq!(&old_app_hash[..], &cresp.data[..]);
    }

    #[test]
    fn query_should_return_proof_for_committed_tx() {
        let (mut app, txaux, _) = deliver_valid_tx();
        let mut endreq = RequestEndBlock::default();
        endreq.set_height(10);
        app.end_block(&endreq);
        let cresp = app.commit(&RequestCommit::default());
        let mut qreq = RequestQuery::new();
        qreq.data = txaux.tx.id().to_vec();
        qreq.path = "store".into();
        qreq.prove = true;
        let qresp = app.query(&qreq);
        assert_eq!(txaux.tx, from_slice(&qresp.value).unwrap());
        let proof = qresp.proof.unwrap();
        assert_eq!(proof.ops.len(), 3);
        assert_eq!(proof.ops[0].data, txaux.tx.id());
        assert_eq!(proof.ops[1].data, cresp.data);
        let mut qreq2 = RequestQuery::new();
        qreq2.data = txaux.tx.id().to_vec();
        qreq2.path = "witness".into();
        let qresp = app.query(&qreq2);
        assert_eq!(qresp.value, to_vec_packed(&txaux.witness).unwrap());
        assert_eq!(proof.ops[2].data, txid_hash(&qresp.value));
    }

}
