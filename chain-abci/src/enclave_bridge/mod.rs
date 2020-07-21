use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponse};

/// TODO: feature-guard when workspaces can be built with --features flag: https://github.com/rust-lang/cargo/issues/5015
pub mod mock;

#[cfg(all(not(feature = "mock-enclave"), feature = "legacy", target_os = "linux"))]
pub mod real;

#[cfg(feature = "edp")]
pub mod edp;

/// Abstracts over communication with an external part that does enclave calls
pub trait EnclaveProxy: Sync + Send + Sized + Clone {
    // sanity check for checking enclave initialization
    fn check_chain(&mut self, network_id: u8) -> Result<(), ()>;
    fn process_request(&mut self, request: IntraEnclaveRequest) -> IntraEnclaveResponse;
}
