use parity_scale_codec::{Decode, Encode};

use chain_core::tx::data::TxId;

/// Configuration options passed to TDBE on startup
#[derive(Debug, Encode, Decode)]
pub struct TdbeStartupConfig {
    /// DNS name of TDBE server for fetching initial data
    pub tdbe_dns_name: Option<String>,
    /// Transaction IDs to fetch from another TDBE server
    pub transaction_ids: Vec<TxId>,
}
