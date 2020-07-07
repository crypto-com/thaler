use parity_scale_codec::{Decode, Encode};

use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::TxId;

pub const TDBE_REQUEST_SIZE: usize = 1024 * 60; // 60 KB (maybe smaller?)

#[derive(Encode, Decode)]
pub enum TdbeRequest {
    /// Fetch all the UTXOs those were spent
    ///
    /// Note: We only need transaction inputs, i.e., the UTXOs those were spent because all other
    /// information should already be avaliable to node from light client.
    GetSpentTransactionOutputs {
        /// Transaction IDs for which to fetch spent UTXOs
        txids: Vec<TxId>,
    },
    /// Fetches keypackage for current node
    GetKeyPackage,
}

#[derive(Encode, Decode)]
pub enum TdbeResponse {
    /// Contains all the UTXOs those were spent corresponding to
    /// `TdbeRequest::GetSpentTransactionOutputs`
    GetSpentTransactionOutputs {
        /// Spent UTXOs
        spent_utxos: Vec<TxoPointer>,
    },
    /// Contains keypackage for current node
    GetKeyPackage {
        /// Raw keypackage data
        key_package: Vec<u8>, // TODO: Concrete `KeyPackage` type?
    },
    /// Error response from TDBE
    Error {
        /// Error message
        message: String,
    },
}
