use serde::{Deserialize, Serialize};

use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponse};

/// TODO: feature-guard when workspaces can be built with --features flag: https://github.com/rust-lang/cargo/issues/5015
pub mod mock;

#[cfg(all(not(feature = "mock-enclave"), feature = "edp", target_os = "linux"))]
pub mod edp;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct TdbeConfig {
    /// Optional TM RPC address of another TDBE server from where to fetch data
    pub remote_rpc_address: Option<String>,
    /// Local TDBE server address to listen on. E.g. `127.0.0.1:3445`
    pub local_listen_address: String,
    /// External TDBE server address, used by remote nodes to send RPC requests. E.g.
    /// `<public_ip>:<public_port>`
    pub external_listen_address: String,
}

/// Abstracts over communication with an external part that does enclave calls
pub trait EnclaveProxy: Sync + Send + Sized {
    // sanity check for checking enclave initialization
    fn check_chain(&mut self, network_id: u8) -> Result<(), ()>;
    fn process_request(&mut self, request: IntraEnclaveRequest) -> IntraEnclaveResponse;
}
