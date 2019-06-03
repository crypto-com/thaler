mod app_init;
mod commit;
mod query;
mod validate_tx;

use abci::*;
use ethbloom::{Bloom, Input};
use log::info;

pub use self::app_init::{ChainNodeApp, ChainNodeState};
use crate::storage::account::AccountStorage;
use crate::storage::account::AccountWrapper;
use crate::storage::tx::StarlingFixedKey;
use crate::storage::COL_TX_META;
use bit_vec::BitVec;
use chain_core::state::account::Account;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::TxAux;
use kvdb::{DBTransaction, KeyValueDB};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Given a db and a DB transaction, it will go through TX inputs and mark them as spent
/// in the TX_META storage.
pub fn spend_utxos(txins: &[TxoPointer], db: Arc<dyn KeyValueDB>, dbtx: &mut DBTransaction) {
    let mut updated_txs = BTreeMap::new();
    for txin in txins.iter() {
        updated_txs
            .entry(txin.id)
            .or_insert_with(|| {
                BitVec::from_bytes(&db.get(COL_TX_META, &txin.id[..]).unwrap().unwrap())
            })
            .set(txin.index, true);
    }
    for (txid, bv) in &updated_txs {
        dbtx.put(COL_TX_META, &txid[..], &bv.to_bytes());
    }
}

/// Given the Account state storage and the current / uncommitted account storage root,
/// it inserts the updated account state into the account storage and returns the new root hash of the account state trie.
pub fn update_account(
    account: Account,
    account_root_hash: &StarlingFixedKey,
    accounts: &mut AccountStorage,
) -> StarlingFixedKey {
    accounts
        .insert(
            Some(account_root_hash),
            &mut [&account.key()],
            &mut [&AccountWrapper(account)],
        )
        .expect("update account")
}

/// TODO: sanity checks in abci https://github.com/tendermint/rust-abci/issues/49
impl abci::Application for ChainNodeApp {
    /// Query Connection: Called on startup from Tendermint.  The application should normally
    /// return the last know state so Tendermint can determine if it needs to replay blocks
    /// to the application.
    fn info(&mut self, _req: &RequestInfo) -> ResponseInfo {
        info!("received info request");
        let mut resp = ResponseInfo::new();
        if let Some(app_state) = &self.last_state {
            resp.last_block_app_hash = app_state.last_apphash.to_vec();
            resp.last_block_height = app_state.last_block_height;
            resp.data = serde_json::to_string(&app_state).expect("serialize app state to json");
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
        // TODO: process RequestBeginBlock -- e.g. rewards for validators? + punishment for malicious ByzantineValidators
        // TODO: Check security implications once https://github.com/tendermint/tendermint/issues/2653 is closed
        let block_time = req
            .header
            .as_ref()
            .expect("Begin block request does not have header")
            .time
            .as_ref()
            .expect("Header does not have a timestamp")
            .seconds;
        self.last_state.as_mut().map(|mut x| x.block_time = block_time)
            .expect("executing begin block, but no app state stored (i.e. no initchain or recovery was executed)");
        ResponseBeginBlock::new()
    }

    /// Consensus Connection: Actually processing the transaction, performing some form of a
    /// state transistion.
    fn deliver_tx(&mut self, _req: &RequestDeliverTx) -> ResponseDeliverTx {
        info!("received delivertx request");
        let mut resp = ResponseDeliverTx::new();
        let mtxaux = ChainNodeApp::validate_tx_req(self, _req, &mut resp);
        if let (0, Some((txaux, fee_acc))) = (resp.code, mtxaux) {
            let mut inittx = self.storage.db.transaction();
            let next_account_root = match &txaux {
                TxAux::TransferTx(tx, _) => {
                    // here the original idea was "conservative" that it "spent" utxos here
                    // but it didn't create utxos for this TX (they are created in commit)
                    spend_utxos(&tx.inputs, self.storage.db.clone(), &mut inittx);
                    self.uncommitted_account_root_hash
                }
                TxAux::DepositStakeTx(tx, _) => {
                    spend_utxos(&tx.inputs, self.storage.db.clone(), &mut inittx);
                    update_account(
                        fee_acc
                            .1
                            .expect("account returned in deposit stake verification"),
                        &self.uncommitted_account_root_hash,
                        &mut self.accounts,
                    )
                }
                TxAux::UnbondStakeTx(_, _) => update_account(
                    fee_acc
                        .1
                        .expect("account returned in unbond stake verification"),
                    &self.uncommitted_account_root_hash,
                    &mut self.accounts,
                ),
                TxAux::WithdrawUnbondedStakeTx(_, _) => update_account(
                    fee_acc
                        .1
                        .expect("account returned in withdraw unbonded stake verification"),
                    &self.uncommitted_account_root_hash,
                    &mut self.accounts,
                ),
            };
            // as self.accounts allows querying against different tree roots
            // the modifications done with "update_account" _should_ be safe, as the final tree root will
            // be persisted in commit.
            // The question is whether it really is -- e.g. if Tendermint/ABCI app crashes during DeliverTX
            // and then it tries to replay the block on the restart, will it cause problems
            // with the account storage (starling / MerkleBIT), because it already persisted those "future" / not-yet-committed account states?
            // TODO: check-verify / test starling persistence safety?
            // TODO: most of these intermediate uncommitted tree roots aren't useful (not exposed for querying) -- prune them / the account storage?
            self.uncommitted_account_root_hash = next_account_root;
            let mut kvpair = KVPair::new();
            kvpair.key = Vec::from(&b"txid"[..]);
            // TODO: "Keys and values in tags must be UTF-8 encoded strings" ?
            kvpair.value = Vec::from(&txaux.tx_id()[..]);
            resp.tags.push(kvpair);
            self.delivered_txs.push(txaux);
            let rewards_pool = &mut self
                .last_state
                .as_mut()
                .expect("deliver tx, but last state not initialized")
                .rewards_pool;
            let new_remaining = (rewards_pool.remaining + fee_acc.0.to_coin())
                .expect("rewards pool + fee greater than max coin?");
            rewards_pool.remaining = new_remaining;
            // this "buffered write" shouldn't persist (persistence done in commit)
            // but should change it in-memory -- TODO: check
            self.storage.db.write_buffered(inittx);
        }
        resp
    }

    /// Consensus Connection: Called at the end of the block.  Often used to update the validator set.
    fn end_block(&mut self, _req: &RequestEndBlock) -> ResponseEndBlock {
        info!("received endblock request");
        let mut resp = ResponseEndBlock::new();
        let mut keys = self
            .delivered_txs
            .iter()
            .filter(|x| match x {
                TxAux::TransferTx(_, _) => true,
                _ => {
                    // TODO: perhaps unbond withdraw should have it in attributes as well?
                    false
                }
            })
            .flat_map(|x| match x {
                TxAux::TransferTx(tx, _) => tx.attributes.allowed_view.iter().map(|x| x.view_key),
                _ => unreachable!(),
            })
            .peekable();
        if keys.peek().is_some() {
            // TODO: explore alternatives, e.g. https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
            let mut bloom = Bloom::default();
            for key in keys {
                bloom.accrue(Input::Raw(&key.serialize()[..]));
            }
            let mut kvpair = KVPair::new();
            kvpair.key = Vec::from(&b"ethbloom"[..]);
            // TODO: "Keys and values in tags must be UTF-8 encoded strings" ?
            kvpair.value = Vec::from(&bloom.data()[..]);
            resp.tags.push(kvpair);
        }
        // TODO: skipchain-based validator changes?
        self.last_state.as_mut().map(|mut x| x.last_block_height = _req.height)
            .expect("executing end block, but no app state stored (i.e. no initchain or recovery was executed)");
        resp
    }

    /// Consensus Connection: Commit the block with the latest state from the application.
    fn commit(&mut self, _req: &RequestCommit) -> ResponseCommit {
        info!("received commit request");
        ChainNodeApp::commit_handler(self, _req)
    }
}
