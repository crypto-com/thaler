use chain_core::init::network::init_chain_id;
use client_common::error::ErrorKind;
use client_common::SecKey;
use client_core::types::WalletKind;
use client_core::wallet::{DefaultWalletClient, WalletClient};
use client_core::HDSeed;
use client_core::Mnemonic;
use secstr::SecUtf8;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::str::FromStr;
pub const MAX_LENGTH: u32 = 1024;
pub const MAX_STRING_LENGTH: u32 = 512;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Buf {
    pub buf: [::std::os::raw::c_uchar; 512usize],
    pub length: ::std::os::raw::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ApiResult {
    pub error: ::std::os::raw::c_int,
    pub value: Buf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HDWallet {
    pub error: ::std::os::raw::c_int,
    pub name: Buf,
    pub value: Buf,
    pub mnemonics: Buf,
    pub viewkey: Buf,
    pub seed: Buf,
    pub enckey: Buf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ApiContext {
    pub error: ::std::os::raw::c_int,
    pub chain_id: Buf,
    pub server_url: Buf,
    pub storage_folder: Buf,
}

use client_common::storage::MemoryStorage;
#[derive(Default)]
pub struct ApiInfo {
    pub chain_id: String,
}
static mut G_DB: Option<MemoryStorage> = None;

/// # Safety
/// this function should not be called inside rust
pub unsafe fn get_string(src: *const c_char) -> String {
    CStr::from_ptr(src).to_string_lossy().into_owned()
}

pub fn copy_string(src: &str, dst: &mut [u8]) {
    dst[..src.len()].clone_from_slice(&src.as_bytes()[..src.len()]);
    dst[src.len()] = 0;
}

pub fn get_string_from_buf(src: &Buf) -> String {
    std::str::from_utf8(&src.buf[0..src.length as usize])
        .expect("convert to string")
        .to_string()
}

fn get_buf(src: &str) -> Buf {
    let mut ret = Buf {
        buf: [0; MAX_STRING_LENGTH as usize],
        length: 0,
    };
    copy_string(src, &mut ret.buf);
    ret.length = src.len() as i32;
    ret
}

fn get_buf_vec(src: &[u8]) -> Buf {
    let mut ret = Buf {
        buf: [0; MAX_STRING_LENGTH as usize],
        length: 0,
    };
    ret.buf[..src.len()].clone_from_slice(&src[..]);
    ret.length = src.len() as i32;
    ret
}

#[no_mangle]
pub extern "C" fn get_network_id() -> ApiResult {
    let networkid = chain_core::init::network::get_network_id();
    let networkid_string = format!("{:2X}", networkid);
    ApiResult {
        error: 0,
        value: get_buf(&networkid_string),
    }
}

/// # Safety
/// this function should not be called inside rust
pub unsafe extern "C" fn do_create_hdwallet(
    name: *const c_char,
    passphrase: *const c_char,
    hdwallet: *mut HDWallet,
) -> Result<(), client_common::error::Error> {
    let name_string = get_string(name);
    let passphrase_string = get_string(passphrase);
    let mnemonic = Mnemonic::new();
    let hd_seed = HDSeed::from(&mnemonic);
    let encoded = hd_seed.as_bytes();
    let storage = G_DB.clone().unwrap();
    let wallet_client = DefaultWalletClient::new_read_only(storage);
    let (enckey, mnemonic) = wallet_client.new_wallet(
        &name_string,
        &SecUtf8::from(passphrase_string),
        WalletKind::HD,
    )?;

    let viewkey = wallet_client.view_key(&name_string, &enckey)?.serialize();
    let e = enckey.unsecure();
    let mut ret = HDWallet {
        error: 0,
        name: get_buf(&name_string),
        value: get_buf(""),
        mnemonics: get_buf(""),
        viewkey: get_buf_vec(&viewkey),
        seed: get_buf_vec(&encoded),
        enckey: get_buf_vec(&e),
    };
    match mnemonic {
        Some(m2) => {
            let m = m2.unsecure_phrase();
            ret.value = get_buf(&m);
            ret.mnemonics = get_buf(&m);
        }
        None => {
            return Err(client_common::error::Error::from(ErrorKind::IoError));
        }
    }
    (*hdwallet) = ret;

    Ok(())
}

/// # Safety
/// this function should not be called inside rust
#[no_mangle]
pub unsafe extern "C" fn create_hdwallet(
    name: *const c_char,
    passphrase: *const c_char,
    hdwallet: *mut HDWallet,
) -> i32 {
    match do_create_hdwallet(name, passphrase, hdwallet) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// # Safety
/// this function should not be called inside rust
pub unsafe extern "C" fn do_make_hdwallet_transfer_address(
    wallet: *mut HDWallet,
) -> Result<ApiResult, client_common::error::Error> {
    let name_string = get_string_from_buf(&(*wallet).name);
    let enckey = (*wallet).enckey.buf[0..(*wallet).enckey.length as usize].to_vec();
    let storage = G_DB.clone().unwrap();
    let wallet_client = DefaultWalletClient::new_read_only(storage);

    let enckey_hex = hex::encode(&enckey);
    let enckey_seckey = SecKey::from_str(&enckey_hex).unwrap();
    let address = wallet_client.new_transfer_address(&name_string, &enckey_seckey)?;

    let ret = ApiResult {
        error: 0,
        value: get_buf(&address.to_string()),
    };
    Ok(ret)
}

/// # Safety
/// this function should not be called inside rust
#[no_mangle]
pub unsafe extern "C" fn make_hdwallet_transfer_address(wallet: *mut HDWallet) -> ApiResult {
    match do_make_hdwallet_transfer_address(wallet) {
        Ok(a) => a,
        Err(b) => ApiResult {
            error: -1,
            value: get_buf(&b.to_string()),
        },
    }
}

/// # Safety
/// this function should not be called inside rust
pub unsafe extern "C" fn do_make_hdwallet_staking_address(
    wallet: *mut HDWallet,
) -> Result<ApiResult, client_common::error::Error> {
    let name_string = get_string_from_buf(&(*wallet).name);
    let enckey = (*wallet).enckey.buf[0..(*wallet).enckey.length as usize].to_vec();
    let storage = G_DB.clone().unwrap();
    let wallet_client = DefaultWalletClient::new_read_only(storage);

    let enckey_hex = hex::encode(&enckey);
    let enckey_seckey = SecKey::from_str(&enckey_hex).unwrap();
    let address = wallet_client.new_staking_address(&name_string, &enckey_seckey)?;

    let ret = ApiResult {
        error: 0,
        value: get_buf(&address.to_string()),
    };
    Ok(ret)
}

/// # Safety
/// this function should not be called inside rust
#[no_mangle]
pub unsafe extern "C" fn make_hdwallet_staking_address(wallet: *mut HDWallet) -> ApiResult {
    match do_make_hdwallet_staking_address(wallet) {
        Ok(a) => a,
        Err(b) => ApiResult {
            error: -1,
            value: get_buf(&b.to_string()),
        },
    }
}

/// # Safety
/// this function should not be called inside rust
#[no_mangle]
pub unsafe extern "C" fn initialize(
    chain_id: *const c_char,
    server: *const c_char,
    storage: *const c_char,
) -> ApiContext {
    let api_chain_id = get_string(chain_id);
    init_chain_id(&api_chain_id);
    let api_server = get_string(server);
    let api_storage = get_string(storage);
    G_DB = Some(MemoryStorage::default());
    ApiContext {
        error: 0,
        chain_id: get_buf(&api_chain_id),
        server_url: get_buf(&api_server),
        storage_folder: get_buf(&api_storage),
    }
}

/// # Safety
/// this function should not be called inside rust
#[no_mangle]
pub unsafe extern "C" fn print_buf(name: *const c_char, buf: *mut Buf) {
    let api_name = get_string(name);
    println!(
        "{}= {}",
        api_name,
        hex::encode(&(*buf).buf[..(*buf).length as usize])
    );
}
