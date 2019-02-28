use zmq::{Socket, Context, REP, Error};
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};
use abci_enclave_protocol::{SubAbciRequest, SubAbciResponse, FLAGS};
use crate::enclave_u::initchain;
use sgx_urts::SgxEnclave;

pub struct TxValidationServer {
    socket: Socket,
    enclave: SgxEnclave
}

impl TxValidationServer {
    pub fn new(connection_str: &str, enclave: SgxEnclave) -> Result<TxValidationServer, Error> {
        println!("Init");
        let ctx = Context::new();
        let socket = ctx.socket(REP)?;
        socket.bind(connection_str)?;
        Ok(TxValidationServer {
            socket,
            enclave
        })
    }

    pub fn execute(&mut self) {
        println!("Running");
        loop {
            if let Ok(msg) = self.socket.recv_bytes(FLAGS) {
                let mcmd: Result<SubAbciRequest, bincode::Error> = deserialize(&msg[..]);
                let mut resp = SubAbciResponse::UnknownRequest;
                if let Ok(SubAbciRequest::InitChain(chain_hex_id)) = mcmd {
                    resp = SubAbciResponse::InitChain(initchain(self.enclave.geteid(), chain_hex_id)); 
                }
                let response = serialize(&resp).expect("serialized valid response");
                self.socket.send(response, FLAGS).expect("reply sending failed");
            }
        }
    }
}