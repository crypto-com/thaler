use enclave_protocol::{EnclaveRequest, EnclaveResponse};

/// mock for testing
pub mod mock;

mod enclave;
/// builtin tx-validation enclave service
pub use enclave::EnclaveAppProxy;

/// Abstracts over communication with an external process that does enclave calls
pub trait EnclaveProxy: Sync + Send + Sized {
    fn process_request(&mut self, request: EnclaveRequest) -> EnclaveResponse;
}
