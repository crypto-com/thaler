use std::borrow::Cow;

use parity_scale_codec::{Decode, Encode};

use chain_core::tx::{data::TxId, TxWithOutputs};

/// Command sent by TDBE to persist a sealed transaction in chain-storage
#[derive(Encode, Decode)]
pub enum PersistenceCommand {
    /// Command to store transaction in chain-storage
    Store {
        /// Transaction ID
        transaction_id: TxId,
        /// Sealed transaction data
        sealed_log: Vec<u8>,
    },
    /// Command to signal completion of catch-up process
    Finish {
        /// Height of last fetched block in catch-up process
        last_fetched_block: u32,
    },
}

/// TDBE request initialized from other TDBE servers (enclave-to-enclave communication)
#[derive(Encode, Decode)]
pub enum TrustedTdbeRequest<'a> {
    /// Fetch all the transactions with outputs
    GetTransactionsWithOutputs {
        /// Transaction IDs for which to fetch all the transactions
        transaction_ids: Cow<'a, [TxId]>,
    },
}

/// Response for `TrustedTdbeRequest`
#[derive(Encode, Decode)]
pub enum TrustedTdbeResponse<'a> {
    /// Contains all the requested transactions with outputs
    GetTransactionsWithOutputs {
        /// Requested transactions
        transactions: Vec<TxWithOutputs>,
    },
    /// Error response from TDBE
    Error {
        /// Error message
        message: Cow<'a, str>,
    },
}

/// TDBE request initialized by untrusted sources
#[derive(Encode, Decode)]
pub enum UntrustedTdbeRequest {
    /// Fetches keypackage for current node
    GetKeyPackage,
}

/// Response for `UntrustedTdbeRequest`
#[derive(Encode, Decode)]
pub enum UntrustedTdbeResponse<'a> {
    /// Contains keypackage for current node
    GetKeyPackage {
        /// Raw keypackage data
        key_package: Cow<'a, [u8]>, // TODO: Concrete `KeyPackage` type?
    },
    /// Error response from TDBE
    Error {
        /// Error message
        message: Cow<'a, str>,
    },
}
