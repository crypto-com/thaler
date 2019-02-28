
#![crate_name = "txvalidationenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![cfg_attr(not(feature = "std"), feature(alloc))]
#![feature(slice_concat_ext)]


#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate sgx_tunittest;
extern crate sgx_types;
extern crate sgx_tse;
extern crate sgx_trts;
extern crate sgx_tseal;
extern crate sgx_rand;

use sgx_types::*;

const TESTNET_HEX_ID: u8 = 0xab;

#[no_mangle]
pub extern "C" fn ecall_initchain(chain_hex_id: u8) -> sgx_status_t {
    if chain_hex_id == TESTNET_HEX_ID {
        sgx_status_t::SGX_SUCCESS
    } else {
        sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    }
}
