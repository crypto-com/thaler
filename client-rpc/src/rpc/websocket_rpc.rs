use futures::future::Future;
use futures::sink::Sink;
use futures::stream::Stream;
use futures::sync::mpsc;
use mpsc::Sender;
use std::thread;
use std::time;
use websocket::result::WebSocketError;
use websocket::{ClientBuilder, OwnedMessage};

use serde_json::{json, Value};
const CONNECTION: &'static str = "ws://localhost:26657/websocket";
const CMD_SUBSCRIBE: &'static str = r#"
    {
        "jsonrpc": "2.0",
        "method": "subscribe",
        "id": "subscribe_reply",
        "params": {
            "query": "tm.event='NewBlock'"
        }
    }"#;
const CMD_BLOCK: &'static str = r#"
    {
        "method": "block",
        "jsonrpc": "2.0",
        "params": [ "2" ],
        "id": "block_reply"
    }"#;
const CMD_STATUS: &'static str = r#"
    {
        "method": "status",
        "jsonrpc": "2.0",
        "params": [ ],
        "id": "status_reply"
    }"#;

// constanct connection
// using ws://localhost:26657/websocket
pub struct WebsocketRpc {}

impl WebsocketRpc {
    pub fn new() -> WebsocketRpc {
        WebsocketRpc {}
    }

    pub fn start_sync(&self, sender: Sender<OwnedMessage>) {
        let mut sink = sender.clone().wait();
        let _child = thread::spawn(move || loop {
            thread::sleep(time::Duration::from_millis(5000));
            println!("get status");
            sink.send(OwnedMessage::Text(CMD_STATUS.to_string()))
                .unwrap();
        });
    }

    pub fn start_refresh(&self, sender: Sender<OwnedMessage>) {
        let mut sink = sender.clone().wait();
        let mut current_block: u64 = 1;
        let mut json: Value = serde_json::from_str(CMD_BLOCK).unwrap();
        let _child = thread::spawn(move || loop {
            thread::sleep(time::Duration::from_millis(1000));
            json["params"] = json!([current_block.to_string()]);
            println!("get block {}", json.to_string());
            sink.send(OwnedMessage::Text(json.to_string())).unwrap();
            current_block += 1 ;
        });
    }

    pub fn parse(&self, value: Value) -> Option<()> {
        let id = value["id"].as_str()?;
        println!("parse {} {}", id, id == "block_reply");
        match id {
            "status_reply" => {
                let height = value["result"]["sync_info"]["latest_block_height"].as_str()?;
                println!("status_reply id={} height={}", id, height);
            }
            "block_reply" => {
                let block_height = value["result"]["block"]["header"]["height"].as_str()?;
                println!("block_reply id={} block_height={}", id, block_height);
            }
            _ => {}
        }

        Some(())
    }
    pub fn run(&self) {
        println!("Connecting to {}", CONNECTION);
        let mut runtime = tokio::runtime::current_thread::Builder::new()
            .build()
            .unwrap();

        // standard in isn't supported in mio yet, so we use a thread
        // see https://github.com/carllerche/mio/issues/321
        let mut channel = mpsc::channel(0);
        // tx, rx
        let (channel_tx, channel_rx) = channel;
        // get synchronous sink
        let mut channel_sink = channel_tx.clone().wait();
        self.start_sync(channel_tx.clone());
        self.start_refresh(channel_tx.clone());

        let runner = ClientBuilder::new(CONNECTION)
            .unwrap()
            .add_protocol("rust-websocket")
            .async_connect_insecure()
            .and_then(|(duplex, _)| {
                channel_sink
                    .send(OwnedMessage::Text(CMD_SUBSCRIBE.to_string()))
                    .unwrap();
                let (sink, stream) = duplex.split();

                stream
                    .filter_map(|message| {
                        match message {
                            OwnedMessage::Text(a) => {
                                let b: Value = serde_json::from_str(a.as_str()).unwrap();
                                //println!("received {}", b);
                                self.parse(b);
                                None
                            }
                            OwnedMessage::Binary(a) => {
                                println!("binary! = {}", hex::encode(a));
                                None
                            }
                            OwnedMessage::Close(e) => Some(OwnedMessage::Close(e)),
                            OwnedMessage::Ping(d) => Some(OwnedMessage::Pong(d)),
                            _ => None,
                        }
                    })
                    .select(channel_rx.map_err(|_| WebSocketError::NoDataAvailable))
                    .forward(sink)
            });
        runtime.block_on(runner).unwrap();
    }
}
