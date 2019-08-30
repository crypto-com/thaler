use crate::rpc::websocket_core::WebsocketCore;
use crate::server::WalletRequest;
use chain_core::state::account::StakedStateAddress;
use client_common::tendermint::Client;
use client_common::Result;
use client_common::{PrivateKey, PublicKey, Storage};
use client_index::BlockHandler;
use futures::future::Future;
use futures::sink::Sink;
use futures::stream::Stream;
use futures::sync::mpsc;

use serde::{Deserialize, Serialize};
use std::thread;
use websocket::result::WebSocketError;
use websocket::{ClientBuilder, OwnedMessage};
/** this handles low level network connection
 packet processing and core works are done in websocket_core
it uses channel to communicate with core
 through send queue
 */
pub const CMD_SUBSCRIBE: &str = r#"
    {
        "jsonrpc": "2.0",
        "method": "subscribe",
        "id": "subscribe_reply",
        "params": {
            "query": "tm.event='NewBlock'"
        } 
    }"#;
pub const CMD_BLOCK: &str = r#"
    {
        "method": "block",
        "jsonrpc": "2.0",
        "params": [ "2" ],
        "id": "block_reply"
    }"#;
pub const CMD_STATUS: &str = r#"
    {
        "method": "status",
        "jsonrpc": "2.0",
        "params": [ ],
        "id": "status_reply"
    }"#;

type MyQueue = std::sync::mpsc::Sender<OwnedMessage>;

#[derive(Clone, Debug)]
pub struct WalletInfo {
    pub name: String,
    pub staking_addresses: Vec<StakedStateAddress>,
    pub view_key: PublicKey,
    pub private_key: PrivateKey,
}
pub type WalletInfos = Vec<WalletInfo>;

#[derive(Serialize, Deserialize)]
pub struct AddWalletCommand {
    pub id: String,
    pub wallet: WalletRequest,
    pub name: String,
    pub staking_addresses: Vec<StakedStateAddress>,
    pub view_key: PublicKey,
    pub private_key: PrivateKey,
}

/** constanct connection
using ws://localhost:26657/websocket
*/
pub struct WebsocketRpc {
    pub core: Option<MyQueue>,
    websocket_url: String,
    my_sender: Option<mpsc::Sender<OwnedMessage>>,
    my_receiver: Option<mpsc::Receiver<OwnedMessage>>,
}

/// handling web-socket
impl WebsocketRpc {
    pub fn new(websocket_url: String) -> Self {
        Self {
            core: None,
            websocket_url,
            my_sender: None,
            my_receiver: None,
        }
    }

    /// launch core thread
    pub fn run<S: Storage + 'static, C: Client + 'static, H: BlockHandler + 'static>(
        &mut self,
        wallets: WalletInfos,
        client: C,
        storage: S,
        block_handler: H,
    ) {
        let channel = mpsc::channel(0);
        // tx, rx
        let (channel_tx, channel_rx) = channel;
        self.my_sender = Some(channel_tx.clone());
        self.my_receiver = Some(channel_rx);

        let mut core =
            WebsocketCore::new(channel_tx.clone(), storage, client, block_handler, wallets);
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
