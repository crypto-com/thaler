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

pub struct WebsocketCore {
    sender: futures::sync::mpsc::Sender<OwnedMessage>,
    my_sender: Sender<OwnedMessage>,
    my_receiver: Receiver<OwnedMessage>,
    old_time: SystemTime,
    old_blocktime: SystemTime,
    current_height: u64,
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
            current_height: 0,
        }
    }

    fn get_latest_height(&self) -> u64 {
        0
    }
    fn save_block(&self, value: &Value) {
        let block_length = serde_json::to_string(&value).unwrap().len();
        let block_height = value["result"]["block"]["header"]["height"]
            .as_str()
            .unwrap();
        println!("save block height={}  size={}", block_height, block_length);
    }

    pub fn get_queue(&self) -> Sender<OwnedMessage> {
        self.my_sender.clone()
    }

    // received
    fn do_parse(&mut self, value: Value) -> Option<()> {
        let id = value["id"].as_str()?;

        match id {
            "status_reply" => {
                let height = value["result"]["sync_info"]["latest_block_height"].as_str()?;
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
    pub fn check_status(&mut self) {
        let mut sink = self.sender.clone().wait();
        sink.send(OwnedMessage::Text(CMD_STATUS.to_string()))
            .unwrap()
    }

    pub fn polling(&mut self) {
        let now = SystemTime::now();
        let diff = now.duration_since(self.old_time).unwrap().as_millis();

        if diff < 2000 {
            return;
        }
        self.old_time = now;
        println!("polling {:?}", diff);
    }

    pub fn polling_blocks(&mut self) {
        let now = SystemTime::now();
        let diff = now.duration_since(self.old_blocktime).unwrap().as_millis();

        if diff < 100 {
            return;
        }
        self.old_blocktime = now;
        self.send_request_block();
    }

    pub fn send_request_block(&mut self) {
        let mut json: Value = serde_json::from_str(CMD_BLOCK).unwrap();
        json["params"] = json!([self.current_height.to_string()]);

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
            self.polling_blocks();
        }
    }
}
