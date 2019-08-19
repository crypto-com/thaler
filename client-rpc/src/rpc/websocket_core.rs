use crate::rpc::websocket_rpc::{WalletInfo, WalletInfos};
use crate::rpc::websocket_rpc::{CMD_BLOCK, CMD_STATUS};
use chain_core::state::account::StakedStateAddress;
use chain_tx_filter::BlockFilter;
use chrono::Local;
use client_common::tendermint::types::Block;
use client_common::tendermint::Client;
use client_common::{BlockHeader, PrivateKey, PublicKey, Result, Storage, Transaction};
use client_index::service::GlobalStateService;
use client_index::BlockHandler;
use futures::sink::Sink;
use mpsc::Receiver;
use mpsc::Sender;
use serde_json::json;
use serde_json::Value;
use std::sync::mpsc;
use std::time;
use std::time::SystemTime;
use websocket::OwnedMessage;

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

pub struct WebsocketCore<S, C, H>
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
    current_height2: u64,
    max_height: u64,
    state: WebsocketState,
    global_state_service: GlobalStateService<S>,
    client: C,
    block_handler: H,
    wallets: Vec<WalletInfo>,
    current_wallet: usize,
}

impl<S, C, H> WebsocketCore<S, C, H>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
{
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

        WebsocketCore {
            sender,
            my_sender,
            my_receiver,
            old_blocktime: SystemTime::now(),
            state_time: SystemTime::now(),
            current_height2: 0,
            max_height: 0,
            state: WebsocketState::ReadyProcess,
            global_state_service: gss,
            client,
            block_handler,
            wallets,
            current_wallet: 0,
        }
    }

    fn get_current_wallet(&self) -> WalletInfo {
        assert!(self.wallets.len() > 0);
        assert!(0 <= self.current_wallet && self.current_wallet < self.wallets.len());
        return self.wallets[self.current_wallet].clone();
    }
    fn get_current_height(&self) -> u64 {
        let wallet = self.get_current_wallet();
        self.global_state_service
            .last_block_height(&wallet.view_key)
            .unwrap()
    }

    fn do_save_block_to_chain(&mut self, value: &Value, kind: &str) {
        // restore as object
        let height: u64 = value["block"]["header"]["height"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        println!("******************* {} {}", height, kind);
        let m = serde_json::to_string(&value).unwrap();
        let m2: Block = serde_json::from_str(&m).unwrap();

        self.write_block(height, &m2);
    }

    pub fn write_block(&self, block_height: u64, block: &Block) -> Result<()> {
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

    pub fn change_to_wait(&mut self) {
        self.state = WebsocketState::WaitProcess;
        self.state_time = SystemTime::now();
    }

    pub fn get_queue(&self) -> Sender<OwnedMessage> {
        self.my_sender.clone()
    }

    // received
    fn do_parse(&mut self, value: Value) -> Option<()> {
        let id = value["id"].as_str()?;
        match id {
            "subscribe_reply#event" => {
                let block = value["result"]["data"]["value"]["block"].clone();
                let height = block["header"]["height"].as_str().unwrap();

                self.do_save_block_to_chain(&value["result"]["data"]["value"], "event");
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
                    self.do_save_block_to_chain(&value["result"], "get block");

                    if self.get_current_height() >= self.max_height {
                        println!("all synced wallet {}.. wait", wallet.name);
                        self.change_to_wait();
                    }
                }
            }
            _ => {}
        }
        None
    }
    pub fn change_wallet(&mut self) {
        println!("change wallet");
        // increase
        self.current_wallet += 1;
        assert!(0 < self.wallets.len());
        self.current_wallet %= self.wallets.len();
    }
    pub fn parse(&mut self, message: OwnedMessage) {
        match message {
            OwnedMessage::Text(a) => {
                let b: Value = serde_json::from_str(a.as_str()).unwrap();
                self.do_parse(b);
            }
            _ => (),
        }
    }
    pub fn prepare_get_blocks(&mut self, height: String) {
        self.max_height = height.parse::<u64>().unwrap();
        if self.get_current_height() < self.max_height {
            self.state = WebsocketState::GetBlocks;

            println!(
                "get blocks current {}  max_height {}",
                self.get_current_height(),
                self.max_height
            );
        } else {
            let w = self.get_current_wallet();
            println!(
                "synced now current wallet {}  current {}  max_height {}   {}",
                w.name,
                self.get_current_height(),
                self.max_height,
                Local::now()
            );
            self.change_to_wait();
            self.change_wallet();
        }
    }
    pub fn check_status(&mut self) {
        let mut sink = self.sender.clone().wait();
        sink.send(OwnedMessage::Text(CMD_STATUS.to_string()))
            .unwrap();
        self.state = WebsocketState::GetStatus;
    }

    pub fn polling(&mut self) {
        match self.state {
            WebsocketState::ReadyProcess => {
                self.check_status();
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

    pub fn polling_get_blocks(&mut self) {
        let now = SystemTime::now();
        let diff = now.duration_since(self.old_blocktime).unwrap().as_millis();

        if diff < BLOCK_REQUEST_TIME {
            return;
        }
        self.old_blocktime = now;
        self.send_request_block();
    }

    pub fn send_request_block(&mut self) {
        let mut json: Value = serde_json::from_str(CMD_BLOCK).unwrap();
        let request = self.get_current_height() + 1;
        json["params"] = json!([request.to_string()]);
        let mut sink = self.sender.clone().wait();
        sink.send(OwnedMessage::Text(json.to_string())).unwrap();
    }

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
