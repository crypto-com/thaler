use crate::rpc::websocket_rpc::{WalletInfo, WalletInfos};
use crate::rpc::websocket_rpc::{CMD_BLOCK, CMD_STATUS};
use crate::server::to_rpc_error;
use chain_core::state::account::StakedStateAddress;
use chain_tx_filter::BlockFilter;
use client_common::tendermint::types::Block;
use client_common::tendermint::Client;
use client_common::{BlockHeader, Result, Storage, Transaction};
use client_common::{Error, ErrorKind};
use client_core::WalletClient;
use client_index::service::GlobalStateService;
use client_index::BlockHandler;
use futures::sink::Sink;
use jsonrpc_core::Result as JsonResult;
use mpsc::Receiver;
use mpsc::Sender;
use secstr::SecUtf8;
use serde_json::json;
use serde_json::Value;
use std::sync::mpsc;
use std::time;
use std::time::SystemTime;
use websocket::OwnedMessage;

/// finite state machine that manages blocks
/// just use one thread to multi-plexing for data and command

/// rust don't allow sharing between threads without mutex
/// so multi-plexed with OwnedMessage

/// Network is handled websocket_rpc

/// not to use too much cpu, it takes some time for waiting
const WAIT_PROCESS_TIME: u128 = 5000; // milli seconds
const BLOCK_REQUEST_TIME: u128 = 10; // milli seconds
const RECEIVE_TIMEOUT: u64 = 10; //  milli seconds
#[derive(Copy, Clone, Debug)]
pub enum WebsocketState {
    ReadyProcess,
    GetStatus,
    GetBlocks,
    WaitProcess,
}

pub struct WebsocketCore<S, C, H, T>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
    T: WalletClient,
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
    wallet_client: T,
}

impl<S, C, H, T> WebsocketCore<S, C, H, T>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
    T: WalletClient,
{
    pub fn new(
        sender: futures::sync::mpsc::Sender<OwnedMessage>,
        storage: S,
        client: C,
        block_handler: H,
        wallets: WalletInfos,
        wallet_client: T,
    ) -> Self {
        let gss = GlobalStateService::new(storage);

        let channel = mpsc::channel();
        // tx, rx
        let (my_sender, my_receiver) = channel;

        WebsocketCore {
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

            wallet_client,
        }
    }

    // to process multiple wallets
    fn get_current_wallet(&self) -> WalletInfo {
        assert!(self.current_wallet < self.wallets.len());
        self.wallets[self.current_wallet].clone()
    }

    // get height from database
    fn get_current_height(&self) -> u64 {
        let wallet = self.get_current_wallet();
        self.global_state_service
            .last_block_height(&wallet.view_key)
            .unwrap()
    }

    // write block to internal database
    fn do_save_block_to_chain(&mut self, block: Block, kind: &str) {
        if self.wallets.is_empty() {
            return;
        }
        // restore as object
        let height: u64 = block.height().unwrap();
        let current = self.get_current_height();
        if height != current + 1 {
            log::info!(
                "drop block {} current={} max={}",
                height,
                current,
                self.max_height
            );
            return;
        }
        log::info!("save block height={} kind={}", height, kind);
        let _ = self.write_block(height, &block);
    }

    // low level block processing
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

    // now one session is complete
    // let's wait some time to next blocks
    pub fn change_to_wait(&mut self) {
        self.state = WebsocketState::WaitProcess;
        self.state_time = SystemTime::now();
    }

    // tx channel for this thread
    pub fn get_queue(&self) -> Sender<OwnedMessage> {
        self.my_sender.clone()
    }

    // because everything is done via channel
    // no mutex is necessary
    // wallet can be added in runtime
    pub fn add_wallet(&mut self, name: String, passphrase: SecUtf8) -> JsonResult<()> {
        log::info!("add_wallet ***** {}", name);
        let view_key = self
            .wallet_client
            .view_key(&name, &passphrase)
            .map_err(to_rpc_error)?;
        let private_key = self
            .wallet_client
            .private_key(&passphrase, &view_key)
            .map_err(to_rpc_error)?
            .ok_or_else(|| Error::from(ErrorKind::WalletNotFound))
            .map_err(to_rpc_error)?;

        let staking_addresses = self
            .wallet_client
            .staking_addresses(&name, &passphrase)
            .map_err(to_rpc_error)?;

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

    // Value is given from websocket_rpc
    // received
    fn do_parse(&mut self, value: Value) -> Option<()> {
        let id = value["id"].as_str()?;
        match id {
            // this is special, it's command
            "add_wallet" => {
                let name = value["wallet"]["name"].as_str().unwrap();
                let _ = self.add_wallet(
                    name.to_string(),
                    value["wallet"]["passphrase"].as_str().unwrap().into(),
                );
            }
            "subscribe_reply#event" => {
                let newblock: Block =
                    serde_json::from_value(value["result"]["data"]["value"].clone()).unwrap();
                self.do_save_block_to_chain(newblock, "event");
            }
            "status_reply" => {
                let height = value["result"]["sync_info"]["latest_block_height"].as_str()?;
                self.prepare_get_blocks(height.to_string());
            }
            "block_reply" => {
                let block = value["result"]["block"].clone();
                if block.is_null() {
                    self.change_to_wait();
                } else {
                    let wallet = self.get_current_wallet();
                    let newblock: Block = serde_json::from_value(value["result"].clone()).unwrap();
                    self.do_save_block_to_chain(newblock, "get block");

                    if self.get_current_height() >= self.max_height {
                        log::info!("all synced wallet {}.. wait", wallet.name);
                        self.change_to_wait();
                    }
                }
            }
            _ => {}
        }
        None
    }
    // proceed next wallet
    pub fn change_wallet(&mut self) {
        log::info!("change wallet");
        // increase
        self.current_wallet += 1;
        assert!(!self.wallets.is_empty());
        self.current_wallet %= self.wallets.len();
    }
    // only process text messages
    // session is handled in websocket_rpc
    pub fn parse(&mut self, message: OwnedMessage) {
        if let OwnedMessage::Text(a) = message {
            let b: Value = serde_json::from_str(a.as_str()).unwrap();
            self.do_parse(b);
        }
    }
    // max height is queried
    // get those blocks from tendermint
    pub fn prepare_get_blocks(&mut self, height: String) {
        self.max_height = height.parse::<u64>().unwrap();
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
    // request status to fetch max height
    pub fn check_status(&mut self) {
        let mut sink = self.sender.clone().wait();
        sink.send(OwnedMessage::Text(CMD_STATUS.to_string()))
            .unwrap();
        self.state = WebsocketState::GetStatus;
    }

    // called regularly, when receive time expires
    pub fn polling(&mut self) {
        match self.state {
            WebsocketState::ReadyProcess => {
                if !self.wallets.is_empty() {
                    self.check_status();
                }
            }
            WebsocketState::WaitProcess => {
                let now = SystemTime::now();
                let diff = now.duration_since(self.state_time).unwrap().as_millis();

                if diff > WAIT_PROCESS_TIME {
                    self.state = WebsocketState::ReadyProcess;
                }
            }
            WebsocketState::GetStatus => {}
            WebsocketState::GetBlocks => self.polling_get_blocks(),
        }
    }

    // called in get blocks state
    pub fn polling_get_blocks(&mut self) {
        let now = SystemTime::now();
        let diff = now.duration_since(self.old_blocktime).unwrap().as_millis();

        if diff < BLOCK_REQUEST_TIME {
            return;
        }
        self.old_blocktime = now;
        self.send_request_block();
    }

    // fetching blocks is handled indivisually
    // in one thread instead of dedicated thread
    pub fn send_request_block(&mut self) {
        let mut json: Value = serde_json::from_str(CMD_BLOCK).unwrap();
        let request = self.get_current_height() + 1;
        json["params"] = json!([request.to_string()]);
        let mut sink = self.sender.clone().wait();
        sink.send(OwnedMessage::Text(json.to_string())).unwrap();
    }

    // decrypt using viewkey
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

    pub fn start(&mut self) {
        loop {
            let _ = self
                .my_receiver
                .recv_timeout(time::Duration::from_millis(RECEIVE_TIMEOUT))
                .map(|a| {
                    self.parse(a);
                });
            self.polling();
        }
    }
}
