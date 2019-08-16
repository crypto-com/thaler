use crate::rpc::websocket_rpc::CMD_STATUS;
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
use std::time;
use std::time::Duration;
use websocket::result::WebSocketError;
use websocket::{ClientBuilder, OwnedMessage};

pub struct WebsocketCore {
    sender: futures::sync::mpsc::Sender<OwnedMessage>,
    my_sender: Sender<OwnedMessage>,
    my_receiver: Receiver<OwnedMessage>,
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
        }
    }
    pub fn get_queue(&self) -> Sender<OwnedMessage> {
        self.my_sender.clone()
    }

    // received
    fn do_parse(&mut self, value: Value) -> Option<()> {
        let id = value["id"].as_str()?;
        println!("parse {} {}", id, id == "block_reply");
        match id {
            "status_reply" => {
                let height = value["result"]["sync_info"]["latest_block_height"].as_str()?;
                println!("core- status_reply id={} height={}", id, height);
            }
            "block_reply" => {
                let block_height = value["result"]["block"]["header"]["height"].as_str()?;
                println!("core- block_reply id={} block_height={}", id, block_height);
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
    pub fn start(&mut self) {
        loop {
            let _ = self
                .my_receiver
                .recv_timeout(time::Duration::from_millis(1000))
                .map(|a| {
                    self.parse(a);
                });
        }
    }
}
