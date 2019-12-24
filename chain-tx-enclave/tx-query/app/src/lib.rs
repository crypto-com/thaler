#[cfg(feature = "mesalock_sgx")]
pub mod enclave_u;
#[cfg(feature = "mesalock_sgx")]
pub use enclave_u::TxQueryEnclave;

#[cfg(not(feature = "mesalock_sgx"))]
pub mod mock_u;
#[cfg(not(feature = "mesalock_sgx"))]
pub use mock_u::TxQueryEnclave;

pub mod server;
