use crate::types::get_string;
use crate::types::CroResult;
use crate::types::{CroFee, CroFeePtr};
pub use chain_core::init::network::Network;
use chain_core::tx::fee::{LinearFee, Milli};
use std::os::raw::c_char;
use std::ptr;
use std::str::FromStr;

/// create fee algorithm
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_create_fee_algorithm(
    fee_out: *mut CroFeePtr,
    constant_string: *const c_char,
    coeff_string: *const c_char,
) -> CroResult {
    let base = get_string(constant_string);
    let coeff = get_string(coeff_string);
    let fee = CroFee {
        fee: LinearFee::new(
            Milli::from_str(&base).expect("read milli from constant"),
            Milli::from_str(&coeff).expect("read milli from coefficient"),
        ),
    };
    let fee_box = Box::new(fee);
    ptr::write(fee_out, Box::into_raw(fee_box));
    CroResult::success()
}

/// estimate fee
/// tx_payload_size: in bytes
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_estimate_fee(fee_ptr: CroFeePtr, tx_payload_size: u32) -> u64 {
    let fee: &mut CroFee = fee_ptr.as_mut().expect("get fee");
    let fee_value = fee
        .fee
        .estimate(tx_payload_size as usize)
        .expect("fee estimate");
    let coin_value: u64 = fee_value.to_coin().into();
    coin_value
}

/// estimate fee after encryption
/// tx_payload_size: in bytes
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_estimate_fee_after_encrypt(
    fee_ptr: CroFeePtr,
    tx_payload_size: u32,
) -> u64 {
    let fee: &mut CroFee = fee_ptr.as_mut().expect("get fee");
    let block_size = 16; // aes block size 16 bytes == 128 bits
    let after_encrypt_size = tx_payload_size + (block_size - (tx_payload_size % block_size));
    let fee_value = fee
        .fee
        .estimate(after_encrypt_size as usize)
        .expect("fee estimate");
    let coin_value: u64 = fee_value.to_coin().into();
    coin_value
}
/// destroy fee
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_destroy_fee_algorithm(fee: CroFeePtr) -> CroResult {
    Box::from_raw(fee);
    CroResult::success()
}
