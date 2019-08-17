use crate::rpc::websocket_rpc::{CMD_BLOCK, CMD_STATUS};
use futures::future::Future;
use futures::sink::Sink;
use futures::stream::Stream;
//use futures::sync::mpsc;
use mpsc::Receiver;
use mpsc::Sender;
use serde_json::Value;
use std::sync::mpsc;
use std::sync::mpsc::channel;
use std::thread;
use std::thread::sleep;
use std::time;
use std::time::Duration;
use std::time::SystemTime;
use websocket::result::WebSocketError;
use websocket::{ClientBuilder, OwnedMessage};

use serde_json::json;
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

pub struct WebsocketCore {
    sender: futures::sync::mpsc::Sender<OwnedMessage>,
    my_sender: Sender<OwnedMessage>,
    my_receiver: Receiver<OwnedMessage>,
    old_time: SystemTime,
    old_blocktime: SystemTime,
    state_time: SystemTime,
    current_height: u64,
    max_height: u64,
    state: WebsocketState,
}

impl WebsocketCore {
    pub fn new(sender: futures::sync::mpsc::Sender<OwnedMessage>) -> WebsocketCore {
        let channel = mpsc::channel();
        // tx, rx
        let (my_sender, my_receiver) = channel;

        WebsocketCore {
            sender,
            my_sender,
            my_receiver,
            old_time: SystemTime::now(),
            old_blocktime: SystemTime::now(),
            state_time: SystemTime::now(),
            current_height: 0,
            max_height: 0,
            state: WebsocketState::ReadyProcess,
        }
    }

    fn get_latest_height(&self) -> u64 {
        0
    }
    fn do_save_block(&mut self, value: &Value, kind: &str) {
        if value.is_null() {
            return;
        }
        let block_length = serde_json::to_string(&value).unwrap().len();
        let block_height = value["header"]["height"].as_str().unwrap();
        let bh = block_height.parse::<u64>().unwrap();
        if bh != self.current_height + 1 {
            return;
        }
        self.current_height = bh;

        let rate = bh as f64 / self.max_height as f64 * 100.0;

        if self.current_height >= self.max_height {
            self.max_height = self.current_height;
        }

        println!(
            "**** {} save block {:.2}% {}/{}  size={}",
            kind, rate, block_height, self.max_height, block_length
        );
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
                self.do_save_block(&block, "event");
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
                    self.do_save_block(&block, "get block");

                    if self.current_height >= self.max_height {
                        println!("all synced.. wait");
                        self.change_to_wait();
                    }
                }
            }
            _ => {}
        }
        None
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
        if self.current_height < self.max_height {
            self.state = WebsocketState::GetBlocks;

            println!(
                "get blocks current {}  max_height {}",
                self.current_height, self.max_height
            );
        } else {
            self.change_to_wait();
            println!("synced now");
        }
    }
    pub fn check_status(&mut self) {
        let mut sink = self.sender.clone().wait();
        sink.send(OwnedMessage::Text(CMD_STATUS.to_string()))
            .unwrap();
        self.state = WebsocketState::GetStatus;
    }

    pub fn polling(&mut self) {
        let now = SystemTime::now();
        let diff = now.duration_since(self.old_time).unwrap().as_millis();

        if diff < 2000 {
            return;
        }
        self.old_time = now;
        self.polling_state();
    }

    pub fn polling_state(&mut self) {
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
            WebsocketState::GetBlocks => {}
        }
    }

    pub fn polling_blocks(&mut self) {
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
        let request = self.current_height + 1;
        json["params"] = json!([request.to_string()]);
        let mut sink = self.sender.clone().wait();
        sink.send(OwnedMessage::Text(json.to_string())).unwrap();
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

            match self.state {
                WebsocketState::GetBlocks => self.polling_blocks(),
                _ => {}
            }
        }
    }
}
