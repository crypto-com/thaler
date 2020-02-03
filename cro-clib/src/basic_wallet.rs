use crate::types::{CroAddress, CroAddressPtr, CroResult};
use chain_core::init::address::RedeemAddress;

use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::address::ExtendedAddr;
use client_common::MultiSigAddress;
use client_common::{PrivateKey, PublicKey};
use std::ptr;

/// # Safety
fn do_cro_basic_create_staking_address(private: PrivateKey) -> Box<CroAddress> {
    let public: PublicKey = PublicKey::from(&private);
    let address: StakedStateAddress = StakedStateAddress::BasicRedeem(RedeemAddress::from(&public));
    match address {
        StakedStateAddress::BasicRedeem(redeem) => {
            // redeem is 20 bytes
            let raw = redeem.to_vec();
            let ret = CroAddress {
                privatekey: private,
                publickey: public,
                raw,
                address: address.to_string(),
            };
            Box::new(ret)
        }
    }
}

/// create staking address
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_basic_create_staking_address(
    address_out: *mut CroAddressPtr,
) -> CroResult {
    let private: PrivateKey = PrivateKey::new().expect("get private key");
    let address: Box<CroAddress> = do_cro_basic_create_staking_address(private);
    ptr::write(address_out, Box::into_raw(address));
    CroResult::success()
}

/// restore staking address
/// 32 bytes
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_basic_restore_staking_address(
    address_out: *mut CroAddressPtr,
    input: *const u8,
) -> CroResult {
    let array: &[u8] = std::slice::from_raw_parts(input, 32);
    let address: Box<CroAddress>;
    match PrivateKey::deserialize_from(array) {
        Ok(deserialized) => address = do_cro_basic_create_staking_address(deserialized),
        Err(_) => return CroResult::fail(),
    }
    ptr::write(address_out, Box::into_raw(address));
    CroResult::success()
}

/// # Safety
fn do_cro_basic_create_transfer_address(private: PrivateKey) -> Box<CroAddress> {
    let public: PublicKey = PublicKey::from(&private);
    let public_keys: Vec<PublicKey> = vec![public.clone()];
    let multi_sig_address: MultiSigAddress =
        MultiSigAddress::new(public_keys, public.clone(), 1).unwrap();
    let address: ExtendedAddr = multi_sig_address.into();
    match address {
        ExtendedAddr::OrTree(hash) => {
            let raw = hash.to_vec(); /*raw is 32 bytes*/
            let ret = CroAddress {
                privatekey: private,
                publickey: public,
                raw,
                address: address.to_string(),
            };
            Box::new(ret)
        }
    }
}

/// create staking address
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_basic_create_transfer_address(
    address_out: *mut CroAddressPtr,
) -> CroResult {
    let private: PrivateKey = PrivateKey::new().expect("get private key");
    let address: Box<CroAddress> = do_cro_basic_create_transfer_address(private);
    ptr::write(address_out, Box::into_raw(address));
    CroResult::success()
}

/// restore transfer address
/// 32 bytes
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_basic_restore_transfer_address(
    address_out: *mut CroAddressPtr,
    input: *const u8,
) -> CroResult {
    let array: &[u8] = std::slice::from_raw_parts(input, 32);
    let address: Box<CroAddress>;
    match PrivateKey::deserialize_from(array) {
        Ok(deserialized) => address = do_cro_basic_create_transfer_address(deserialized),
        Err(_) => return CroResult::fail(),
    }
    ptr::write(address_out, Box::into_raw(address));
    CroResult::success()
}

/// # Safety
fn do_cro_basic_create_viewkey(private: PrivateKey) -> Box<CroAddress> {
    let public: PublicKey = PublicKey::from(&private);
    let raw: Vec<u8> = public.serialize(); /* raw is 65 bytes*/
    let ret = CroAddress {
        privatekey: private,
        publickey: public.clone(),
        raw,
        address: public.to_string(),
    };
    Box::new(ret)
}

/// create viewkey, which is for encrypted tx
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_basic_create_viewkey(address_out: *mut CroAddressPtr) -> CroResult {
    let private: PrivateKey = PrivateKey::new().expect("get private key");
    let address = do_cro_basic_create_viewkey(private);
    ptr::write(address_out, Box::into_raw(address));
    CroResult::success()
}

/// restore viewkey
/// 32 bytes
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_basic_restore_viewkey(
    address_out: *mut CroAddressPtr,
    input: *const u8,
) -> CroResult {
    let array: &[u8] = std::slice::from_raw_parts(input, 32);
    let address: Box<CroAddress>;
    match PrivateKey::deserialize_from(array) {
        Ok(deserialized) => address = do_cro_basic_create_viewkey(deserialized),
        Err(_) => return CroResult::fail(),
    }
    ptr::write(address_out, Box::into_raw(address));
    CroResult::success()
}
