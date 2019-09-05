//! auto sync core
//! polling the latest state
//! change wallets and continue syncing

use crate::auto_sync_data::WalletInfo;
use crate::auto_sync_data::{
    AddWalletCommand, AutoSyncDataShared, AutoSyncSendQueue, AutoSyncSendQueueShared, WalletInfos,
    BLOCK_REQUEST_TIME, CMD_BLOCK, CMD_STATUS, RECEIVE_TIMEOUT, WAIT_PROCESS_TIME,
};

use crate::service::GlobalStateService;
use crate::BlockHandler;

use chain_tx_filter::BlockFilter;
use client_common::tendermint::types::Block;
use client_common::tendermint::Client;
use client_common::ErrorKind;
use client_common::{BlockHeader, Result, Storage, Transaction};
use client_common::{PrivateKey, PublicKey};
use futures::sink::Sink;
use jsonrpc_core::Result as JsonResult;
use mpsc::Receiver;
use mpsc::Sender;
use serde_json::json;
use serde_json::Value;
use std::sync::mpsc;
use std::time;
use std::time::SystemTime;
use websocket::OwnedMessage;

use chain_core::state::account::StakedStateAddress;
use client_common::ResultExt;

/**  finite state machine that manages blocks
just use one thread to multi-plexing for data and command

rust don't allow sharing between threads without mutex
so multi-plexed with OwnedMessage

 Network is handled websocket_rpc

 not to use too much cpu, it takes some time for waiting
 */

/// finite state
#[derive(Copy, Clone, Debug)]
enum WebsocketState {
    /// initial state
    ReadyProcess,
    /// getting status
    GetStatus,
    /// getting blocks
    GetBlocks,
    /// wait some time to prevent using 100% cpu
    WaitProcess,
}

/// automatic sync
pub struct AutoSynchronizerCore<S, C, H>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    sender: AutoSyncSendQueueShared,
    my_sender: Sender<OwnedMessage>,
    my_receiver: Receiver<OwnedMessage>,
    old_blocktime: SystemTime,
    state_time: SystemTime,

    max_height: u64,
    state: WebsocketState,
    global_state_service: GlobalStateService<S>,
    client: C,
    block_handler: H,
    wallets: WalletInfos,
    current_wallet: usize,

    data: AutoSyncDataShared,
}

/// auto-sync impl
impl<S, C, H> AutoSynchronizerCore<S, C, H>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    /// create auto sync
    pub fn new(
        sender: AutoSyncSendQueueShared,
        storage: S,
        client: C,
        block_handler: H,
        wallets: WalletInfos,
        data: AutoSyncDataShared,
    ) -> Self {
        let gss = GlobalStateService::new(storage);

        let channel = mpsc::channel();
        // tx, rx
        let (my_sender, my_receiver) = channel;

        AutoSynchronizerCore {
            sender,
            my_sender,
            my_receiver,
            old_blocktime: SystemTime::now(),
            state_time: SystemTime::now(),

            max_height: 0,
            state: WebsocketState::ReadyProcess,
            global_state_service: gss,
            client,
            block_handler,
            wallets,
            current_wallet: 0,
            data,
        }
    }

    /// to process multiple wallets
    fn get_current_wallet(&self) -> WalletInfo {
        assert!(self.current_wallet < self.wallets.len());
        let keys: Vec<String> = self.wallets.keys().cloned().collect();
        let key: String = keys[self.current_wallet].clone();
        self.wallets[&key].clone()
    }

    /// get height from database
    fn get_current_height(&self) -> u64 {
        let wallet = self.get_current_wallet();
        self.global_state_service
            .last_block_height(&wallet.view_key)
            .expect("get current height")
    }

    /// write block to internal database
    fn do_save_block_to_chain(&mut self, block: Block, kind: &str) -> Result<()> {
        if self.wallets.is_empty() {
            return Ok(());
        }
        // restore as object
        let height: u64 = block.height()?;
        let current = self.get_current_height();
        if height != current + 1 {
            log::info!(
                "drop block {} current={} max={}",
                height,
                current,
                self.max_height
            );
            return Ok(());
        }
        // now height ok, extend max height
        if height > self.max_height {
            self.max_height = height;
        }

        // update information
        {
            let mut data = self.data.lock().unwrap();
            data.current_height = height;
            data.max_height = self.max_height;
            data.wallet = self.get_current_wallet().name;
            if data.max_height > 0 {
                data.progress = (data.current_height as f64) / (data.max_height as f64);
            } else {
                data.progress = 0.0;
            }
            log::info!(
                "save block kind={} wallet={} height={}/{}  progress={:.4}%",
                kind,
                data.wallet,
                data.current_height,
                data.max_height,
                data.progress * 100.0
            );
        }

        self.write_block(height, &block)
    }

    /// low level block processing
    pub fn write_block(&self, block_height: u64, block: &Block) -> Result<()> {
        let app_hash = block.app_hash();
        let block_results = self.client.block_results(block_height)?;

        let block_time = block.time();

        let transaction_ids = block_results.transaction_ids()?;
        let block_filter = block_results.block_filter()?;

        let wallet = self.get_current_wallet();
        let unencrypted_transactions = self.check_unencrypted_transactions(
            &block_filter,
            wallet.staking_addresses.as_slice(),
            block,
        )?;

        let block_header = BlockHeader {
            app_hash,
            block_height,
            block_time,
            transaction_ids,
            block_filter,
            unencrypted_transactions,
        };

        self.block_handler
            .on_next(block_header, &wallet.view_key, &wallet.private_key)?;
        Ok(())
    }

    /// now one session is complete
    /// let's wait some time to next blocks
    pub fn change_to_wait(&mut self) {
        self.state = WebsocketState::WaitProcess;
        self.state_time = SystemTime::now();
    }

    /// tx channel for this thread
    pub fn get_queue(&self) -> Sender<OwnedMessage> {
        self.my_sender.clone()
    }
    /// because everything is done via channel
    /// no mutex is necessary
    /// wallet can be added in runtime
    pub fn add_wallet(
        &mut self,
        name: String,
        staking_addresses: Vec<StakedStateAddress>,
        view_key: PublicKey,
        private_key: PrivateKey,
    ) -> JsonResult<()> {
        log::info!("add_wallet ***** {}", name);

        let info = WalletInfo {
            name: name.to_string(),
            staking_addresses,
            view_key: view_key.clone(),
            private_key,
        };

        // upsert
        self.wallets.insert(info.name.clone(), info);
        log::info!("wallets length {}", self.wallets.len());
        Ok(())
    }

    /// Value is given from websocket_rpc
    /// received
    fn do_parse(&mut self, value: Value) -> Result<()> {
        let id = value["id"].as_str().chain(|| {
            (
                ErrorKind::DeserializationError,
                format!("Unable to deserialize `id` from RPC data: {}", value),
            )
        })?;
        match id {
            // this is special, it's command
            "add_wallet" => {
                let info: AddWalletCommand = serde_json::from_value(value).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to deserialize add_wallet from json value",
                    )
                })?;
                let private_key = PrivateKey::deserialize_from(&info.private_key)
                    .expect("Unable to deserialize private key from byte array");

                let _ = self.add_wallet(
                    info.name,
                    info.staking_addresses,
                    info.view_key,
                    private_key,
                );
            }
            "subscribe_reply#event" => {
                let new_block: Block = serde_json::from_value(
                    value["result"]["data"]["value"].clone(),
                )
                .chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        format!("Unable to deserialize `block` from RPC data: {}", value),
                    )
                })?;
                self.do_save_block_to_chain(new_block, "event")?;
            }
            "status_reply" => {
                let height = value["result"]["sync_info"]["latest_block_height"]
                    .as_str()
                    .chain(|| {
                        (
                            ErrorKind::DeserializationError,
                            format!(
                                "Unable to deserialize `latest_block_height` from RPC data: {}",
                                value
                            ),
                        )
                    })?;
                self.prepare_get_blocks(height.to_string());
            }
            "block_reply" => {
                let block = value["result"]["block"].clone();
                if block.is_null() {
                    self.change_to_wait();
                } else {
                    let wallet = self.get_current_wallet();
                    let new_block: Block =
                        serde_json::from_value(value["result"].clone()).chain(|| {
                            (
                                ErrorKind::DeserializationError,
                                format!("Unable to deserialize `block` from RPC data: {}", value),
                            )
                        })?;
                    self.do_save_block_to_chain(new_block, "get block")?;

                    if self.get_current_height() >= self.max_height {
                        log::info!("all synced wallet {}.. wait", wallet.name);
                        self.change_to_wait();
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
    /// proceed next wallet
    pub fn change_wallet(&mut self) {
        log::info!("change wallet");
        // increase
        self.current_wallet += 1;
        assert!(!self.wallets.is_empty());
        self.current_wallet %= self.wallets.len();
    }
    /// only process text messages
    /// session is handled in websocket_rpc
    pub fn parse(&mut self, message: OwnedMessage) -> Result<()> {
        if let OwnedMessage::Text(a) = message {
            let b: Value = serde_json::from_str(a.as_str()).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to parse websocket data into json value",
                )
            })?;
            return self.do_parse(b);
        }
        Ok(())
    }
    /** max height is queried
    get those blocks from tendermint
    */
    pub fn prepare_get_blocks(&mut self, height: String) {
        self.max_height = height
            .parse::<u64>()
            .expect("get height in preparing a block");
        if self.get_current_height() < self.max_height {
            self.state = WebsocketState::GetBlocks;

            log::info!(
                "get blocks current {}  max_height {}",
                self.get_current_height(),
                self.max_height
            );
        } else {
            let w = self.get_current_wallet();
            log::info!(
                "synced now current wallet {}  current {}  max_height {}",
                w.name,
                self.get_current_height(),
                self.max_height,
            );
            self.change_to_wait();
            self.change_wallet();
        }
    }
    /// request status to fetch max height
    pub fn check_status(&mut self) -> Result<()> {
        let mut sendqueue: Option<futures::sync::mpsc::Sender<OwnedMessage>> = None;
        {
            let mut data = self.sender.lock().unwrap();
            sendqueue = data.queue.clone();
        }
        if sendqueue.is_none() {
            return Ok(());
        }
        let mut sink = sendqueue.unwrap().wait();
        sink.send(OwnedMessage::Text(CMD_STATUS.to_string()))
            .chain(|| {
                (
                    ErrorKind::InternalError,
                    "Unable to send message to futures::sink",
                )
            })?;
        self.state = WebsocketState::GetStatus;
        Ok(())
    }

    /// called regularly, when receive time expires
    pub fn polling(&mut self) -> Result<()> {
        match self.state {
            WebsocketState::ReadyProcess => {
                if !self.wallets.is_empty() {
                    self.check_status()?;
                }
                Ok(())
            }
            WebsocketState::WaitProcess => {
                let now = SystemTime::now();
                let diff = now
                    .duration_since(self.state_time)
                    .expect("get duration time")
                    .as_millis();

                if diff > WAIT_PROCESS_TIME {
                    self.state = WebsocketState::ReadyProcess;
                }
                Ok(())
            }
            WebsocketState::GetStatus => Ok(()),
            WebsocketState::GetBlocks => self.polling_get_blocks(),
        }
    }

    /// called in get blocks state
    pub fn polling_get_blocks(&mut self) -> Result<()> {
        let now = SystemTime::now();
        let diff = now
            .duration_since(self.old_blocktime)
            .expect("get duration time")
            .as_millis();

        if diff < BLOCK_REQUEST_TIME {
            return Ok(());
        }
        self.old_blocktime = now;
        self.send_request_block()
    }

    /** fetching blocks is handled indivisually
    in one thread instead of dedicated thread
    */
    pub fn send_request_block(&mut self) -> Result<()> {
        let mut sendqueue: Option<futures::sync::mpsc::Sender<OwnedMessage>> = None;
        {
            let mut data = self.sender.lock().unwrap();
            sendqueue = data.queue.clone();
        }
        if sendqueue.is_none() {
            return Ok(());
        }
        let mut sink = sendqueue.unwrap().wait();
        let mut json: Value = serde_json::from_str(CMD_BLOCK).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize `CMD_BLOCK` into json value",
            )
        })?;
        let request = self.get_current_height() + 1;
        json["params"] = json!([request.to_string()]);
        sink.send(OwnedMessage::Text(json.to_string())).chain(|| {
            (
                ErrorKind::InternalError,
                "Unable to send message to futures::sink",
            )
        })?;
        Ok(())
    }

    /// decrypt using viewkey
    fn check_unencrypted_transactions(
        &self,
        block_filter: &BlockFilter,
        staking_addresses: &[StakedStateAddress],
        block: &Block,
    ) -> Result<Vec<Transaction>> {
        for staking_address in staking_addresses {
            if block_filter.check_staked_state_address(staking_address) {
                return block.unencrypted_transactions();
            }
        }

        Ok(Default::default())
    }

    /// start syncing
    pub fn start(&mut self) {
        loop {
            let _ = self
                .my_receiver
                .recv_timeout(time::Duration::from_millis(RECEIVE_TIMEOUT))
                .map(|a| {
                    self.parse(a).expect("correct parsing");
                });
            let _ = self.polling();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::auto_sync_data::AutoSyncData;
    use chain_core::init::address::RedeemAddress;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::*;
    use std::sync::Arc;
    use std::sync::Mutex;

    struct MockClient;

    impl Client for MockClient {
        fn genesis(&self) -> Result<Genesis> {
            unreachable!()
        }

        fn status(&self) -> Result<Status> {
            unreachable!()
        }

        fn block(&self, _height: u64) -> Result<Block> {
            unreachable!()
        }

        fn block_batch<'a, T: Iterator<Item = &'a u64>>(&self, _heights: T) -> Result<Vec<Block>> {
            unreachable!()
        }

        fn block_results(&self, _height: u64) -> Result<BlockResults> {
            unreachable!()
        }

        fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
            &self,
            _heights: T,
        ) -> Result<Vec<BlockResults>> {
            unreachable!()
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<BroadcastTxResult> {
            Ok(BroadcastTxResult {
                code: 0,
                data: String::from(""),
                hash: String::from(""),
                log: String::from(""),
            })
        }

        fn query(&self, _path: &str, _data: &[u8]) -> Result<QueryResult> {
            unreachable!()
        }
    }

    struct MockBlockHandler {}
    impl BlockHandler for MockBlockHandler {
        fn on_next(
            &self,
            _block_header: BlockHeader,
            _view_key: &PublicKey,
            _private_key: &PrivateKey,
        ) -> Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn check_sync_wallet() {
        let storage = MemoryStorage::default();
        let client = MockClient {};
        let handler = MockBlockHandler {};
        let data = Arc::new(Mutex::new(AutoSyncData::new()));
        let channel = futures::sync::mpsc::channel(0);
        let (channel_tx, _channel_rx) = channel;
        let mut core =
            AutoSynchronizerCore::new(channel_tx.clone(), storage, client, handler, vec![], data);

        let private_key = PrivateKey::new().unwrap();
        let view_key = PublicKey::from(&private_key);
        let staking_address = StakedStateAddress::BasicRedeem(RedeemAddress::from(&view_key));
        core.add_wallet("a".into(), vec![staking_address], view_key, private_key)
            .expect("auto sync add wallet");

        core.change_wallet();
        assert!(core.current_wallet == 0);
        assert!(core.get_current_wallet().name == "a".to_string());
    }

    #[test]
    fn check_change_to_wait() {
        let storage = MemoryStorage::default();
        let client = MockClient {};
        let handler = MockBlockHandler {};
        let data = Arc::new(Mutex::new(AutoSyncData::new()));
        let channel = futures::sync::mpsc::channel(0);
        let (channel_tx, _channel_rx) = channel;
        let mut core =
            AutoSynchronizerCore::new(channel_tx.clone(), storage, client, handler, vec![], data);
        core.change_to_wait();

        match core.state {
            WebsocketState::WaitProcess => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn check_prepare_get_blocks() {
        let storage = MemoryStorage::default();
        let client = MockClient {};
        let handler = MockBlockHandler {};
        let data = Arc::new(Mutex::new(AutoSyncData::new()));
        let channel = futures::sync::mpsc::channel(0);
        let (channel_tx, _channel_rx) = channel;
        let mut core =
            AutoSynchronizerCore::new(channel_tx.clone(), storage, client, handler, vec![], data);

        let private_key = PrivateKey::new().unwrap();
        let view_key = PublicKey::from(&private_key);
        let staking_address = StakedStateAddress::BasicRedeem(RedeemAddress::from(&view_key));
        core.add_wallet("a".into(), vec![staking_address], view_key, private_key)
            .expect("auto sync add wallet");

        core.prepare_get_blocks("1".into());

        match core.state {
            WebsocketState::GetBlocks => assert!(true),
            _ => assert!(false),
        }
    }
}
