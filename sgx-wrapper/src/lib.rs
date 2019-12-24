#![cfg_attr(all(feature = "mesalock_sgx", not(target_env = "sgx")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![cfg_attr(feature = "mesalock_sgx", feature(proc_macro_hygiene))]

//! Developer friendly enclave development guidelines:
//! - Enable `no_std` and use `sgx_tstd` as `std` when feature `mesalock_sgx` is on.
//! - Use `Box`, `Vec`, `Mutex` from wrapper.
//! - Use compile time environment variables (like `MOCK_KEY` and `NETWORK_HEX_ID`) from wrapper.
//!   (Because procedure macros in expression not stable yet)
//! - Only use wrapped version of sgx features, current support:
//!   - random bytes generator: `os_rng_fill`
//!   - seal/unseal: `SealedData`/`UnsealedData`
//!
//! Then the enclave can be built both as real sgx enclave and normal crate.

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

#[macro_use]
extern crate lazy_static;

#[cfg(not(feature = "mesalock_sgx"))]
mod mock;
#[cfg(not(feature = "mesalock_sgx"))]
use mock as impl_;

#[cfg(feature = "mesalock_sgx")]
mod sgx;
#[cfg(feature = "mesalock_sgx")]
use sgx as impl_;

pub use impl_::{os_rng_fill, SealedData, UnsealedData, MOCK_KEY, NETWORK_HEX_ID};

#[cfg(not(feature = "mesalock_sgx"))]
pub use std::sync::{Mutex, RwLock};
#[cfg(feature = "mesalock_sgx")]
pub use std::sync::{SgxMutex as Mutex, SgxRwLock as RwLock};

pub use std::prelude::v1::{Box, Vec};

#[cfg(feature = "mesalock_sgx")]
mod cert;
#[cfg(feature = "mesalock_sgx")]
pub mod sgx_attest;
#[cfg(feature = "mesalock_sgx")]
pub use sgx_attest as attest;

#[cfg(not(feature = "mesalock_sgx"))]
pub mod mock_attest;
#[cfg(not(feature = "mesalock_sgx"))]
pub use mock_attest as attest;
