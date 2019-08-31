/**
automatic sync

how to use
1. create and store channel
let mut web = AutoSynchronizer::new(url);
web.run(tendermint_client, storage.clone(), block_handler);
self.websocket_queue = Some(web.core.as_mut().unwrap().clone());

2. activate sync
send this json as text to channel
and sync will begin
wallets can be added in runtime

json!(AddWalletCommand {
    id: "add_wallet".to_string(),
    name: request.name,
    staking_addresses,
    view_key,
    private_key,
}
*/
use crate::service::GlobalStateService;
use crate::BlockHandler;
use chain_core::state::account::StakedStateAddress;
use chain_tx_filter::BlockFilter;
use client_common::tendermint::types::Block;
use client_common::tendermint::Client;
use client_common::{BlockHeader, Result, Storage, Transaction};
use client_common::{Error, ErrorKind};
use client_common::{PrivateKey, PublicKey};
use failure::ResultExt;
use futures::future::Future;
use futures::sink::Sink;
use futures::stream::Stream;
use jsonrpc_core::Result as JsonResult;
use mpsc::Receiver;
use mpsc::Sender;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use std::sync::mpsc;
use std::thread;
use std::time;
use std::time::SystemTime;
use websocket::result::WebSocketError;
use websocket::ClientBuilder;
use websocket::OwnedMessage;

/// give add wallet command via this queue
pub type AutoSyncQueue = std::sync::Mutex<Option<std::sync::mpsc::Sender<OwnedMessage>>>;

#[derive(Clone, Debug)]
/// Wallet Information
pub struct WalletInfo {
    /// name of wallet
    pub name: String,
    /// staking address                     
    pub staking_addresses: Vec<StakedStateAddress>,
    /// view-key
    pub view_key: PublicKey,
    /// private-key           
    pub private_key: PrivateKey,
}
/// Wallet infos
pub type WalletInfos = Vec<WalletInfo>;

/// giving command via channel
#[derive(Serialize, Deserialize)]
pub struct AddWalletCommand {
    /// id of this command
    pub id: String,
    /// wallet name
    pub name: String,
    /// staking addresses
    pub staking_addresses: Vec<StakedStateAddress>,
    /// view key
    pub view_key: PublicKey,
    /// private key
    pub private_key: Vec<u8>,
}
/// subscribe command
pub const CMD_SUBSCRIBE: &str = r#"
    {
        "jsonrpc": "2.0",
        "method": "subscribe",
        "id": "subscribe_reply",
        "params": {
            "query": "tm.event='NewBlock'"
        } 
    }"#;

/// block command
pub const CMD_BLOCK: &str = r#"
    {
        "method": "block",
        "jsonrpc": "2.0",
        "params": [ "2" ],
        "id": "block_reply"
    }"#;

/// status command
pub const CMD_STATUS: &str = r#"
    {
        "method": "status",
        "jsonrpc": "2.0",
        "params": [ ],
        "id": "status_reply"
    }"#;

/// giving command to auto-sync
pub type MyQueue = std::sync::mpsc::Sender<OwnedMessage>;

/**  finite state machine that manages blocks
just use one thread to multi-plexing for data and command

rust don't allow sharing between threads without mutex
so multi-plexed with OwnedMessage

 Network is handled websocket_rpc

 not to use too much cpu, it takes some time for waiting
 */

/// wait process interval
const WAIT_PROCESS_TIME: u128 = 5000; // milli seconds
/// block request interval
const BLOCK_REQUEST_TIME: u128 = 10; // milli seconds
/// receive polling interval
const RECEIVE_TIMEOUT: u64 = 10; //  milli seconds

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
struct AutoSynchronizerCore<S, C, H>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    sender: futures::sync::mpsc::Sender<OwnedMessage>,
    my_sender: Sender<OwnedMessage>,
    my_receiver: Receiver<OwnedMessage>,
    old_blocktime: SystemTime,
    state_time: SystemTime,

    max_height: u64,
    state: WebsocketState,
    global_state_service: GlobalStateService<S>,
    client: C,
    block_handler: H,
    wallets: Vec<WalletInfo>,
    current_wallet: usize,
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
        sender: futures::sync::mpsc::Sender<OwnedMessage>,
        storage: S,
        client: C,
        block_handler: H,
        wallets: WalletInfos,
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
        }
    }

    /// to process multiple wallets
    fn get_current_wallet(&self) -> WalletInfo {
        assert!(self.current_wallet < self.wallets.len());
        self.wallets[self.current_wallet].clone()
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
        log::info!("save block height={} kind={}", height, kind);
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

        self.wallets.push(info.clone());
        log::info!("wallets length {}", self.wallets.len());
        Ok(())
    }

    /// Value is given from websocket_rpc
    /// received
    fn do_parse(&mut self, value: Value) -> Result<()> {
        let id = value["id"]
            .as_str()
            .ok_or_else(|| Error::from(ErrorKind::RpcError))?;
        match id {
            // this is special, it's command
            "add_wallet" => {
                let info: AddWalletCommand =
                    serde_json::from_value(value).expect("get AddWalletCommand");
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
                let newblock: Block =
                    serde_json::from_value(value["result"]["data"]["value"].clone())
                        .context(ErrorKind::RpcError)?;
                self.do_save_block_to_chain(newblock, "event")?;
            }
            "status_reply" => {
                let height = value["result"]["sync_info"]["latest_block_height"]
                    .as_str()
                    .ok_or_else(|| Error::from(ErrorKind::RpcError))?;
                self.prepare_get_blocks(height.to_string());
            }
            "block_reply" => {
                let block = value["result"]["block"].clone();
                if block.is_null() {
                    self.change_to_wait();
                } else {
                    let wallet = self.get_current_wallet();
                    let newblock: Block = serde_json::from_value(value["result"].clone())
                        .context(ErrorKind::RpcError)?;
                    self.do_save_block_to_chain(newblock, "get block")?;

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
            let b: Value = serde_json::from_str(a.as_str()).context(ErrorKind::RpcError)?;
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
        let mut sink = self.sender.clone().wait();
        sink.send(OwnedMessage::Text(CMD_STATUS.to_string()))
            .context(ErrorKind::RpcError)?;
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
        let mut json: Value = serde_json::from_str(CMD_BLOCK).context(ErrorKind::RpcError)?;
        let request = self.get_current_height() + 1;
        json["params"] = json!([request.to_string()]);
        let mut sink = self.sender.clone().wait();
        sink.send(OwnedMessage::Text(json.to_string()))
            .context(ErrorKind::RpcError)?;
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

/** constanct connection
using ws://localhost:26657/websocket
*/
pub struct AutoSynchronizer {
    /// core
    pub core: Option<MyQueue>,
    /// websocket url
    websocket_url: String,
    /// websocket sender
    my_sender: Option<futures::sync::mpsc::Sender<OwnedMessage>>,
    /// websocket receiver
    my_receiver: Option<futures::sync::mpsc::Receiver<OwnedMessage>>,
}

/// handling web-socket
impl AutoSynchronizer {
    /// send json via channel
    pub fn send_json(websocket_queue: &AutoSyncQueue, data: serde_json::Value) {
        let sendqoption = websocket_queue.lock().unwrap();
        assert!(sendqoption.is_some());
        let sendq = sendqoption.as_ref().unwrap();
        sendq
            .send(OwnedMessage::Text(serde_json::to_string(&data).unwrap()))
            .unwrap();
    }
    /// get send queue
    pub fn get_send_queue(&mut self) -> Option<std::sync::mpsc::Sender<OwnedMessage>> {
        assert!(self.core.is_some());
        Some(self.core.as_mut().unwrap().clone())
    }
    /// create auto sync
    pub fn new(websocket_url: String) -> Self {
        Self {
            /// core
            core: None,
            /// websocket url
            websocket_url,
            /// websocket sender
            my_sender: None,
            /// websocket receiver
            my_receiver: None,
        }
    }

    /// launch core thread
    pub fn run<S: Storage + 'static, C: Client + 'static, H: BlockHandler + 'static>(
        &mut self,
        client: C,
        storage: S,
        block_handler: H,
    ) {
        let channel = futures::sync::mpsc::channel(0);
        // tx, rx
        let (channel_tx, channel_rx) = channel;
        self.my_sender = Some(channel_tx.clone());
        self.my_receiver = Some(channel_rx);

        let mut core =
            AutoSynchronizerCore::new(channel_tx.clone(), storage, client, block_handler, vec![]);
        // save send_queue to communicate with core
        self.core = Some(core.get_queue());

        let _child = thread::spawn(move || {
            core.start();
        });

        assert!(self.core.is_some());
    }

    /// activate tokio websocket
    pub fn run_network(&mut self) -> Result<()> {
        log::info!("Connecting to {}", self.websocket_url);
        let mut runtime = tokio::runtime::current_thread::Builder::new()
            .build()
            .expect("get tokio builder");
        // get synchronous sink
        assert!(self.my_sender.is_some());
        assert!(self.my_receiver.is_some());
        let channel_tx = self.my_sender.as_ref().expect("get ref").clone();
        let channel_rx = self.my_receiver.take().expect("take");
        let mut channel_sink = channel_tx.clone().wait();

        let runner = ClientBuilder::new(&self.websocket_url)
            .expect("client-builder new")
            .add_protocol("rust-websocket")
            .async_connect_insecure()
            .and_then(|(duplex, _)| {
                channel_sink
                    .send(OwnedMessage::Text(CMD_SUBSCRIBE.to_string()))
                    .expect("send to channel sink");
                let (sink, stream) = duplex.split();

                stream
                    .filter_map(|message| match message {
                        OwnedMessage::Text(a) => {
                            if let Some(core) = self.core.as_ref() {
                                core.send(OwnedMessage::Text(a.clone())).expect("core send");
                            }

                            None
                        }
                        OwnedMessage::Binary(_a) => None,
                        OwnedMessage::Close(e) => Some(OwnedMessage::Close(e)),
                        OwnedMessage::Ping(d) => Some(OwnedMessage::Pong(d)),
                        _ => None,
                    })
                    .select(channel_rx.map_err(|_| WebSocketError::NoDataAvailable))
                    .forward(sink)
            });
        let _ = runtime.block_on(runner).expect("tokio block_on");
        Ok(())
    }
}
