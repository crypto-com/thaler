use parity_scale_codec::{Decode, Encode};

/// Configuration options passed to TDBE on startup
#[derive(Debug, Encode, Decode)]
pub struct TdbeStartupConfig {
    /// Optional TM RPC address of another TDBE server from where to fetch data
    pub remote_rpc_address: Option<String>,
}
