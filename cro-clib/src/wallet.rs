use crate::types::get_string;
use crate::types::{CroAccount, CroAddress, CroAddressPtr, CroHDWallet, CroHDWalletPtr, CroResult};
use chain_core::init::address::RedeemAddress;
use chain_core::init::network::Network;
use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::address::ExtendedAddr;
use client_common::MultiSigAddress;
use client_core::{HDSeed, Mnemonic};
use secstr::SecUtf8;
use std::os::raw::c_char;
use std::ptr;

/// create hd wallet
/// minimum  300 byte-length is necessary
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_create_hdwallet(
    wallet_out: *mut CroHDWalletPtr,
    mnemonics: *mut u8,
    mnemonics_length: u32,
) -> CroResult {
    let mnemonic = Mnemonic::new();
    let phrase = mnemonic.unsecure_phrase();
    if phrase.as_bytes().len() >= mnemonics_length as usize {
        return CroResult::fail();
    }
    ptr::write_bytes(mnemonics, 0, mnemonics_length as usize);
    let wallet = CroHDWallet {
        seed: HDSeed::from(&mnemonic),
    };
    let wallet_box = Box::new(wallet);
    ptr::write(wallet_out, Box::into_raw(wallet_box));
    ptr::copy_nonoverlapping(
        phrase.as_bytes().as_ptr(),
        mnemonics,
        phrase.as_bytes().len(),
    );
    CroResult::success()
}

#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_restore_hdwallet(
    mnemonics_string: *const c_char,
    wallet_out: *mut CroHDWalletPtr,
) -> CroResult {
    let mnemonics = get_string(mnemonics_string);
    let mnemonics_sec = SecUtf8::from(mnemonics);
    let mnemonic = Mnemonic::from_secstr(&mnemonics_sec).expect("get mnemonic from secstr");
    let wallet = CroHDWallet {
        seed: HDSeed::from(&mnemonic),
    };
    let wallet_box = Box::new(wallet);
    ptr::write(wallet_out, Box::into_raw(wallet_box));
    CroResult::success()
}

/// create staking address from bip44 hdwallet
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_create_staking_address(
    wallet_ptr: CroHDWalletPtr,
    network: Network,
    address_out: *mut CroAddressPtr,
    index: u32,
) -> CroResult {
    if wallet_ptr.is_null() {
        return CroResult::fail();
    }
    let wallet = wallet_ptr.as_mut().expect("get wallet");
    let (public, private) = wallet
        .seed
        .derive_key_pair(network, CroAccount::Staking as u32, index)
        .expect("derive key pair");
    let address = StakedStateAddress::BasicRedeem(RedeemAddress::from(&public));

    match address {
        StakedStateAddress::BasicRedeem(redeem) => {
            assert!(20 == redeem.0.len());
            let raw = redeem.to_vec();

            let ret = CroAddress {
                privatekey: private,
                publickey: public,
                raw,
                address: address.to_string(),
            };
            let address_box = Box::new(ret);
            ptr::write(address_out, Box::into_raw(address_box));
            CroResult::success()
        }
    }
}

/// create utxo address from bip44 wallet, which is for withdrawal, transfer amount
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_create_transfer_address(
    wallet_ptr: CroHDWalletPtr,
    network: Network,
    address_out: *mut CroAddressPtr,
    index: u32,
) -> CroResult {
    if wallet_ptr.is_null() {
        return CroResult::fail();
    }
    let wallet = wallet_ptr.as_mut().expect("get wallet");
    let (public, private) = wallet
        .seed
        .derive_key_pair(network, CroAccount::Transfer as u32, index)
        .expect("derive key pair");
    let public_keys = vec![public.clone()];
    let multi_sig_address =
        MultiSigAddress::new(public_keys, public.clone(), 1).expect("create multi sig address");

    let address: ExtendedAddr = multi_sig_address.into();

    match address {
        ExtendedAddr::OrTree(hash) => {
            let raw = hash.to_vec();
            // this is H256 hash
            assert!(32 == raw.len());

            let ret = CroAddress {
                privatekey: private,
                publickey: public,
                raw,
                address: address.to_string(),
            };
            let address_box = Box::new(ret);
            ptr::write(address_out, Box::into_raw(address_box));

            CroResult::success()
        }
    }
}

/// create viewkey, which is for encrypted tx
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_create_viewkey(
    wallet_ptr: CroHDWalletPtr,
    network: Network,
    address_out: *mut CroAddressPtr,
    index: u32,
) -> CroResult {
    if wallet_ptr.is_null() {
        return CroResult::fail();
    }
    let wallet = wallet_ptr.as_mut().expect("get wallet");
    let (public, private) = wallet
        .seed
        .derive_key_pair(network, CroAccount::Viewkey as u32, index)
        .expect("derive key pair");
    let raw: Vec<u8> = public.serialize();
    assert!(65 == raw.len());
    let ret = CroAddress {
        privatekey: private,
        publickey: public.clone(),
        raw,
        address: public.to_string(),
    };
    let address_box = Box::new(ret);
    ptr::write(address_out, Box::into_raw(address_box));
    CroResult::success()
}

/// destroy bip44 hdwallet
#[no_mangle]
/// # Safety
/// hdwallet: previously allocated hdwallet
pub unsafe extern "C" fn cro_destroy_hdwallet(hdwallet: CroHDWalletPtr) -> CroResult {
    Box::from_raw(hdwallet);
    CroResult::success()
}

/// destroy address
#[no_mangle]
/// # Safety
/// addr: previously allocated address
pub unsafe extern "C" fn cro_destroy_address(addr: CroAddressPtr) -> CroResult {
    Box::from_raw(addr);
    CroResult::success()
}
