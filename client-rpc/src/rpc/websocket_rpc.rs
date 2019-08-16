use crate::rpc::websocket_core::WebsocketCore;
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
pub const CONNECTION: &'static str = "ws://localhost:26657/websocket";
pub const CMD_SUBSCRIBE: &'static str = r#"
    {
        "jsonrpc": "2.0",
        "method": "subscribe",
        "id": "subscribe_reply",
        "params": {
            "query": "tm.event='NewBlock'"
        }
    }"#;
pub const CMD_BLOCK: &'static str = r#"
    {
        "method": "block",
        "jsonrpc": "2.0",
        "params": [ "2" ],
        "id": "block_reply"
    }"#;
pub const CMD_STATUS: &'static str = r#"
    {
        "method": "status",
        "jsonrpc": "2.0",
        "params": [ ],
        "id": "status_reply"
    }"#;

type MyQueue = std::sync::mpsc::Sender<OwnedMessage>;

// constanct connection
// using ws://localhost:26657/websocket
pub struct WebsocketRpc {
    core: Option<MyQueue>,
}

impl WebsocketRpc {
    pub fn new() -> WebsocketRpc {
        WebsocketRpc { core: None }
    }

    pub fn start_sync(
        &mut self,
        sender: Sender<OwnedMessage>,
    ) -> std::sync::mpsc::Sender<OwnedMessage> {
        let mut core = WebsocketCore::new(sender.clone());
        self.core = Some(core.get_queue());
        let ret = core.get_queue().clone();
        let _child = thread::spawn(move || {
            core.start();
        });
        ret
    }

    pub fn run(&mut self) {
        println!("Connecting to {}", CONNECTION);
        let mut runtime = tokio::runtime::current_thread::Builder::new()
            .build()
            .unwrap();
        let channel = mpsc::channel(0);
        // tx, rx
        let (channel_tx, channel_rx) = channel;
        // get synchronous sink
        let mut channel_sink = channel_tx.clone().wait();
        self.start_sync(channel_tx.clone());

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
                    .filter_map(|message| match message {
                        OwnedMessage::Text(a) => {
                            self.core.as_ref().map(|core| {
                                core.send(OwnedMessage::Text(a.clone())).unwrap();
                            });
                            None
                        }
                        OwnedMessage::Binary(a) => None,
                        OwnedMessage::Close(e) => Some(OwnedMessage::Close(e)),
                        OwnedMessage::Ping(d) => Some(OwnedMessage::Pong(d)),
                        _ => None,
                    })
                    .select(channel_rx.map_err(|_| WebSocketError::NoDataAvailable))
                    .forward(sink)
            });
        runtime.block_on(runner).unwrap();
    }
}
