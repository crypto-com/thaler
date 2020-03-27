use crate::transaction_build::schnorr_sign;
use crate::types::get_string;
use crate::types::{CroAddress, CroAddressPtr, CroDepositTx, CroDepositTxPtr, CroResult};
use chain_core::init::coin::Coin;
pub use chain_core::init::network::Network;
use chain_core::state::account::{DepositBondTx, StakedStateAddress, StakedStateOpAttributes};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::{input::TxoPointer, output::TxOut};
use chain_core::tx::witness::{TxInWitness, TxWitness};
use client_common::{ErrorKind, Result, ResultExt};
use client_common::{SignedTransaction, Transaction};
use client_core::transaction_builder::WitnessedUTxO;
use parity_scale_codec::Encode;
use std::convert::From;
use std::os::raw::c_char;
use std::ptr;
use std::str::FromStr;

/// tx_ptr: tx TxoPointer
/// output: minimum 1000 bytes
/// output_length: actual tx length
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_tx_complete_signing_deposit(
    tx_ptr: CroDepositTxPtr,
    output: *mut u8,
    output_length: *mut u32,
) -> CroResult {
    let user_tx: &mut CroDepositTx = tx_ptr.as_mut().expect("get tx");
    let mut witnesses: Vec<TxInWitness> = vec![];
    for txin in &user_tx.txin {
        if let Some(value) = &txin.witness {
            witnesses.push(value.clone());
        }
    }
    assert!(witnesses.len() == user_tx.txin.len());
    let transaction = user_tx.tx.clone();
    let signed_transaction =
        SignedTransaction::DepositStakeTransaction(transaction, TxWitness::from(witnesses));

    let encoded: Vec<u8> = signed_transaction.encode();
    ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len());
    (*output_length) = encoded.len() as u32;
    CroResult::success()
}

/// network: network id  ex) 0xab
/// to_address_user: staking address, null terminated string  , ex) 0x1ad06eef15492a9a1ed0cfac21a1303198db8840
fn create_tx_encoded_signed_deposit(network: u8, to_address_string: &str) -> Result<CroDepositTx> {
    let to_address = StakedStateAddress::from_str(to_address_string).chain(|| {
        (
            ErrorKind::DeserializationError,
            format!("Unable to deserialize to_address ({})", to_address_string),
        )
    })?;

    let tx_core = DepositBondTx {
        inputs: vec![],
        to_staked_account: to_address,
        attributes: StakedStateOpAttributes::new(network),
    };
    let tx = CroDepositTx {
        txin: vec![],
        tx: tx_core,
    };
    Ok(tx)
}

/// create deposit tx
/// network: network id  ex) 0xab
/// to_address_user: staking address, null terminated string  , ex) 0x1ad06eef15492a9a1ed0cfac21a1303198db8840
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_create_tx_deposit(
    tx_out: *mut CroDepositTxPtr,
    network: u8,
    to_address_user: *const c_char,
) -> CroResult {
    let to_address_string = get_string(to_address_user);
    match create_tx_encoded_signed_deposit(network, &to_address_string) {
        Ok(tx) => {
            let tx_box = Box::new(tx);
            ptr::write(tx_out, Box::into_raw(tx_box));
            CroResult::success()
        }
        Err(_) => CroResult::fail(),
    }
}

/// txid_hex: txid in hex string
/// txindex: which utxo in tx which txid_hex points
/// addr, coin: txid_hex + txindex points this utxo (address, coin value)
fn add_txin_deposit(
    tx: &mut CroDepositTx,
    txid_hex: &str,
    txindex: u16,
    addr: &str,
    coin: u64,
) -> Result<()> {
    let txid = hex::decode(&txid_hex).chain(|| {
        (
            ErrorKind::DeserializationError,
            "Unable to decode hex of txid",
        )
    })?;
    assert!(32 == txid.len());

    let mut txid_bytes: [u8; 32] = [0; 32];
    txid_bytes.copy_from_slice(&txid[0..32]);
    let txin_pointer = TxoPointer::new(txid_bytes, txindex as usize);
    let txin = TxOut::new(
        ExtendedAddr::from_str(&addr).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to decode extended addr",
            )
        })?,
        Coin::new(coin).chain(|| (ErrorKind::DeserializationError, "Unable to decode coin"))?,
    );

    tx.tx.inputs.push(txin_pointer.clone());
    let utxo = WitnessedUTxO {
        prev_txo_pointer: txin_pointer,
        prev_tx_out: txin,
        witness: None,
        threshold: 1,
    };
    tx.txin.push(utxo);
    assert!(tx.tx.inputs.len() == tx.txin.len());
    Ok(())
}

/// add txin
/// txid_string: 64 length hex-char , 32 bytes
/// addr_string: transfer address
/// coin: carson unit  for example) 1_0000_0000 carson = 1 cro, 1 carson = 0.0000_0001 cro
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_tx_add_txin_deposit(
    tx_ptr: CroDepositTxPtr,
    txid_string: *const c_char,
    txindex: u16,
    addr_string: *const c_char,
    coin: u64,
) -> CroResult {
    let mut tx = tx_ptr.as_mut().expect("get tx");
    let txid_hex = get_string(txid_string);
    let addr = get_string(addr_string);
    match add_txin_deposit(&mut tx, &txid_hex, txindex, &addr, coin) {
        Ok(_) => CroResult::success(),
        Err(_) => CroResult::fail(),
    }
}

fn sign_txin_deposit(
    address: &CroAddress,
    user_tx: &mut CroDepositTx,
    which_tx_in_user: u16,
) -> Result<()> {
    let which_tx_in: usize = which_tx_in_user as usize;
    assert!(which_tx_in < user_tx.txin.len());

    let tx = Transaction::DepositStakeTransaction(user_tx.tx.clone());
    let witness: TxInWitness = schnorr_sign(&tx, &address.publickey, &address.privatekey)?;
    user_tx.txin[which_tx_in].witness = Some(witness);
    Ok(())
}

/// sign for each txin
/// address_ptr: privatekey which will sign
/// tx_ptr: which tx to sign?
/// which_tx_in_user: which txin inside tx?
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_tx_sign_txin_deposit(
    address_ptr: CroAddressPtr,
    tx_ptr: CroDepositTxPtr,
    which_tx_in_user: u16,
) -> CroResult {
    let mut user_tx: &mut CroDepositTx = tx_ptr.as_mut().expect("get tx");
    let address: &CroAddress = address_ptr.as_mut().expect("get address");
    match sign_txin_deposit(&address, &mut user_tx, which_tx_in_user) {
        Ok(_) => CroResult::success(),
        Err(_) => CroResult::fail(),
    }
}

/// destroy tx
/// tx: previously allocated tx
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_destroy_tx_deposit(tx: CroDepositTxPtr) -> CroResult {
    Box::from_raw(tx);
    CroResult::success()
}
