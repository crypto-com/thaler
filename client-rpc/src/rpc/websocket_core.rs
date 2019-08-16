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
            current_height: 1,
            max_height: 0,
            state: WebsocketState::ReadyProcess,
        }
    }

    fn get_latest_height(&self) -> u64 {
        0
    }
    fn save_block(&mut self, value: &Value) {
        let block_length = serde_json::to_string(&value).unwrap().len();
        let block_height = value["result"]["block"]["header"]["height"]
            .as_str()
            .unwrap();
        let bh = block_height.parse::<u64>().unwrap();

        let rate = bh as f64 / self.max_height as f64 * 100.0;
        println!(
            "save block {:.2}% {}/{}  size={}",
            rate, block_height, self.max_height, block_length
        );

        if bh >= self.max_height {
            self.wait();
        }
    }

    pub fn wait(&mut self) {
        self.state = WebsocketState::WaitProcess;
        self.state_time = SystemTime::now();
    }

    pub fn get_queue(&self) -> Sender<OwnedMessage> {
        self.my_sender.clone()
    }

    // received
    fn do_parse(&mut self, value: Value) -> Option<()> {
        let id = value["id"].as_str()?;
        //println!("do_parse {}", value.to_string());
        match id {
            "subscribe_reply#event" => {
                let block = value["result"]["data"]["value"]["block"].to_string();
                println!("receive new block {:?}", block.to_string());
            }
            "status_reply" => {
                let height = value["result"]["sync_info"]["latest_block_height"].as_str()?;
                println!("receive status height={}", height);
                self.prepare_get_blocks(height.to_string());
            }
            "block_reply" => {
                let block_height = value["result"]["block"]["header"]["height"].as_str()?;
                self.save_block(&value);
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
        self.state = WebsocketState::GetBlocks;
        self.max_height = height.parse::<u64>().unwrap();
        //    self.current_height = 1;
    }
    pub fn check_status(&mut self) {
        println!("check status");
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
        println!("polling diff={} state={:?}", diff, self.state);
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

                println!("wait...");
                if diff > 10000 {
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

        if diff < 10 {
            return;
        }
        self.old_blocktime = now;
        self.send_request_block();
    }

    pub fn send_request_block(&mut self) {
        let mut json: Value = serde_json::from_str(CMD_BLOCK).unwrap();
        json["params"] = json!([self.current_height.to_string()]);
        //println!("{}", json.to_string());
        let mut sink = self.sender.clone().wait();
        sink.send(OwnedMessage::Text(json.to_string())).unwrap();
        self.current_height += 1;
    }

    pub fn start(&mut self) {
        loop {
            let _ = self
                .my_receiver
                .recv_timeout(time::Duration::from_millis(10))
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
