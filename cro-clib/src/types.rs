use chain_core::state::account::DepositBondTx;
use chain_core::tx::data::Tx;
use chain_core::tx::fee::{LinearFee, Milli};
use client_common::{PrivateKey, PublicKey};
use client_core::transaction_builder::WitnessedUTxO;
use client_core::HDSeed;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::os::raw::c_int;
pub type CroHDWalletPtr = *mut CroHDWallet;
pub type CroAddressPtr = *mut CroAddress;
pub type CroTxPtr = *mut CroTx;
pub type CroDepositTxPtr = *mut CroDepositTx;
pub type CroFeePtr = *mut CroFee;

pub const SUCCESS: i32 = 0;
pub const FAIL: i32 = -1;

pub type CroString = [u8; 200];
/// account types
#[repr(C)]
pub enum CroAccount {
    /// Account for transfer address
    Transfer = 0,
    /// Account for staking address
    Staking = 1,
    /// Account for viewkey
    Viewkey = 2,
}

#[derive(Clone)]
pub struct CroHDWallet {
    pub seed: HDSeed,
}

#[derive(Clone)]
pub struct CroAddress {
    pub privatekey: PrivateKey,
    pub publickey: PublicKey,
    pub raw: Vec<u8>,
    pub address: String,
}

/// TODO: other states (jailed, unjail) will be added
#[repr(C)]
#[derive(Clone)]
pub struct CroStakedState {
    pub nonce: u64,
    pub bonded: u64,
    pub unbonded: u64,
    pub unbonded_from: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct CroResult {
    result: c_int,
}
impl CroResult {
    pub fn success() -> CroResult {
        CroResult { result: SUCCESS }
    }
    pub fn fail() -> CroResult {
        CroResult { result: FAIL }
    }
}

/// # Safety
pub unsafe fn get_string(src: *const c_char) -> String {
    CStr::from_ptr(src).to_string_lossy().into_owned()
}

#[derive(Clone)]
pub struct CroTx {
    pub txin: Vec<WitnessedUTxO>, // TxoPointer, TxOut, TxInWitness
    // contains TxoPointer(in), TxOut(out), attribites(viewkey)
    pub tx: Tx,
}

#[derive(Clone)]
pub struct CroDepositTx {
    pub txin: Vec<WitnessedUTxO>, // TxoPointer, TxOut, TxInWitness
    // contains TxoPointer(in), TxOut(out), attribites(viewkey)
    pub tx: DepositBondTx,
}

#[derive(Clone)]
pub struct CroFee {
    pub fee: LinearFee,
}

impl Default for CroFee {
    fn default() -> Self {
        let fee = LinearFee::new(Milli::new(0, 0), Milli::new(0, 0));
        CroFee { fee }
    }
}

/// 0: zero, 100.0: complete
/// return: 0: OK, -1: Error
pub type ProgressCallback = extern "C" fn(f32) -> i32;
