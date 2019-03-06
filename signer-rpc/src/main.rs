//! # Usage
//! ## Transaction generation
//! Send `POST` request on `http://127.0.0.1/` with following data
//! ```
//! {
//!    "method": "generateTransaction",
//!    "jsonrpc": "2.0",
//!    "params": [{
//!    	  "name": "crypto",
//!    	  "passphrase": "crypto",
//!    	  "signature_types": ["ecdsa"],
//!    	  "transaction": {
//!    	  	 "chain_id": "ab",
//!    	  	 "inputs": [{
//!    	  	 	 "id": "81b24228affefa62a981b5e85013f83cb91ea26435954b2f99369606af06afbd",
//!    	  	 	 "index": 1
//!    	  	 }],
//!    	  	 "outputs": [{
//!    	  	 	 "address": "138dcaba2c8fb315a173f34fb3b07720bcab63fb",
//!    	  	 	 "address_type": "redeem",
//!    	  	 	 "value": 20,
//!    	  	 	 "valid_from": null
//!    	  	 }]
//!    	  }
//!    }],
//!    "id": "dontcare1"
//! }
//! ```
//!
//! ## Address generation
//! Send `POST` request on `http://127.0.0.1/` with following data
//! ```
//! {
//!    "method": "generateAddress",
//!    "jsonrpc": "2.0",
//!    "params": [{
//!    	  "name": "crypto",
//!    	  "passphrase": "crypto"
//!    }],
//!    "id": "dontcare1"
//! }
//! ```
//!
//! ## Address retrieval
//! Send `POST` request on `http://127.0.0.1/` with following data
//! ```
//! {
//!    "method": "getAddress",
//!    "jsonrpc": "2.0",
//!    "params": [{
//!    	  "name": "crypto",
//!    	  "passphrase": "crypto"
//!    }],
//!    "id": "dontcare1"
//! }
//! ```
mod address_rpc;
mod command;
mod transaction_rpc;

use command::Command;

use failure::Error;
use quest::error;
use structopt::StructOpt;

fn main() {
    if let Err(err) = execute() {
        error(&format!("Error: {}", err));
    }
}

fn execute() -> Result<(), Error> {
    let command = Command::from_args();
    command.execute()
}
