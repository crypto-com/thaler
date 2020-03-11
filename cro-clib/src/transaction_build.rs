use crate::types::get_string;
use crate::types::{CroAddress, CroAddressPtr, CroResult};
use crate::types::{CroTx, CroTxPtr};
use chain_core::init::coin::Coin;
pub use chain_core::init::network::Network;
use chain_core::tx::data::access::{TxAccess, TxAccessPolicy};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::witness::TxInWitness;
use chain_core::tx::witness::TxWitness;
use client_common::SignedTransaction;
use client_common::{ErrorKind, Result, ResultExt};
use client_common::{MultiSigAddress, Transaction};
use client_common::{PrivateKey, PrivateKeyAction, PublicKey};
use client_core::transaction_builder::WitnessedUTxO;
use parity_scale_codec::Encode;
use std::convert::From;
use std::os::raw::c_char;
use std::ptr;
use std::str::FromStr;
/// create tx
/// tx_out: previous allocated Tx
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_create_tx(tx_out: *mut CroTxPtr, network: u8) -> CroResult {
    let tx_core = chain_core::tx::data::Tx {
        inputs: vec![],
        outputs: vec![],
        attributes: TxAttributes::new_with_access(network, vec![]),
    };
    let tx = CroTx {
        txin: vec![],
        tx: tx_core,
    };
    let tx_box = Box::new(tx);
    ptr::write(tx_out, Box::into_raw(tx_box));
    CroResult::success()
}

/// txid_hex: txid in hex string
/// txindex: which utxo in tx which txid_hex points
/// addr, coin: txid_hex + txindex points this utxo (address, coin value)
fn add_txin(tx: &mut CroTx, txid_hex: &str, txindex: u16, addr: &str, coin: u64) -> Result<()> {
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
    };
    tx.txin.push(utxo);
    assert!(tx.tx.inputs.len() == tx.txin.len());
    Ok(())
}

/// add txin
/// txid_string: null terminated string, 64 length hex-char , 32 bytes
/// addr_string: null terminated string, transfer address, ex) dcro1dfclvnmj77nfypp0na3ke2fl7nxe787aglynvr7hzvflukg34fqqnrnjek
/// coin: carson unit  for example) 1_0000_0000 carson = 1 cro, 1 carson = 0.0000_0001 cro
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_tx_add_txin(
    tx_ptr: CroTxPtr,
    txid_string: *const c_char,
    txindex: u16,
    addr_string: *const c_char,
    coin: u64,
) -> CroResult {
    let mut tx = tx_ptr.as_mut().expect("get tx");
    let txid_hex = get_string(txid_string);
    let addr = get_string(addr_string);
    match add_txin(&mut tx, &txid_hex, txindex, &addr, coin) {
        Ok(_) => CroResult::success(),
        Err(_) => CroResult::fail(),
    }
}

/// add txin in bytes
/// txid: txid in raw bytes, it's 32 bytes
/// txindex: which utxo in tx which txid_hex points
/// addr, coin: txid_hex + txindex points this utxo (address, coin value)
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_tx_add_txin_raw(
    tx_ptr: CroTxPtr,
    txid: [u8; 32],
    txindex: u16,
    addr: [u8; 32],
    coin: u64,
) -> CroResult {
    let tx = tx_ptr.as_mut().expect("get tx");
    let txin_pointer = TxoPointer::new(txid, txindex as usize);
    let txin = TxOut::new(
        ExtendedAddr::OrTree(addr),
        Coin::new(coin).expect("get coin in cro_tx_add_txin"),
    );

    tx.tx.inputs.push(txin_pointer.clone());
    let utxo = WitnessedUTxO {
        prev_txo_pointer: txin_pointer,
        prev_tx_out: txin,
        witness: None,
    };
    tx.txin.push(utxo);
    assert!(tx.tx.inputs.len() == tx.txin.len());
    CroResult::success()
}

/// add viewkey in string, which you can get from client-cli
/// viewkey_string: null terminated string
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_tx_add_viewkey(
    tx_ptr: CroTxPtr,
    viewkey_string: *const c_char,
) -> CroResult {
    let tx = tx_ptr.as_mut().expect("get tx");
    let viewkey = get_string(viewkey_string);
    let hex: Vec<u8>;
    if let Ok(value) = hex::decode(&viewkey) {
        hex = value;
    } else {
        return CroResult::fail();
    }
    assert!(33 == hex.len());
    let pubkey: secp256k1::PublicKey =
        secp256k1::PublicKey::from_slice(&hex[..]).expect("get public key");

    let policy = TxAccessPolicy {
        view_key: pubkey,
        access: TxAccess::AllData,
    };
    tx.tx.attributes.allowed_view.push(policy);

    CroResult::success()
}

/// add viewkey in bytes
/// viewkey: 32 raw bytes
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_tx_add_viewkey_raw(tx_ptr: CroTxPtr, viewkey: [u8; 33]) -> CroResult {
    let tx = tx_ptr.as_mut().expect("get tx");
    let pubkey: secp256k1::PublicKey =
        secp256k1::PublicKey::from_slice(&viewkey).expect("get public key");
    let policy = TxAccessPolicy {
        view_key: pubkey,
        access: TxAccess::AllData,
    };
    tx.tx.attributes.allowed_view.push(policy);

    CroResult::success()
}

/// extract bytes from signed tx
/// this output is encrypted with tx-query-app
/// can be broadcast to the network
/// output: raw bytes buffer, minimum 1000 bytes
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_tx_complete_signing(
    tx_ptr: CroTxPtr,
    output: *mut u8,
    output_length: *mut u32,
) -> CroResult {
    let user_tx: &mut CroTx = tx_ptr.as_mut().expect("get tx");
    let mut witnesses: Vec<TxInWitness> = vec![];
    for txin in &user_tx.txin {
        if let Some(value) = &txin.witness {
            witnesses.push(value.clone());
        }
    }
    assert!(witnesses.len() == user_tx.txin.len());
    let signed_transaction =
        SignedTransaction::TransferTransaction(user_tx.tx.clone(), TxWitness::from(witnesses));
    let encoded: Vec<u8> = signed_transaction.encode();
    ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len());
    (*output_length) = encoded.len() as u32;
    CroResult::success()
}

/// user_tx: previous allocated tx
fn sign_txin(address: &CroAddress, user_tx: &mut CroTx, which_tx_in_user: u16) -> Result<()> {
    let which_tx_in: usize = which_tx_in_user as usize;
    assert!(which_tx_in < user_tx.txin.len());
    let tx = Transaction::TransferTransaction(user_tx.tx.clone());
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
pub unsafe extern "C" fn cro_tx_sign_txin(
    address_ptr: CroAddressPtr,
    tx_ptr: CroTxPtr,
    which_tx_in_user: u16,
) -> CroResult {
    let mut user_tx: &mut CroTx = tx_ptr.as_mut().expect("get tx");
    let address: &CroAddress = address_ptr.as_mut().expect("get address");
    match sign_txin(&address, &mut user_tx, which_tx_in_user) {
        Ok(_) => CroResult::success(),
        Err(_) => CroResult::fail(),
    }
}

/// TODO: it's only for 1 of 1 , code for other multiple signers(m/n) will be added
pub fn schnorr_sign(
    tx: &Transaction,
    public_key: &PublicKey,
    private_key: &PrivateKey,
) -> Result<TxInWitness> {
    let public_keys: Vec<PublicKey> = vec![public_key.clone()];
    let multi_sig_address = MultiSigAddress::new(public_keys.to_vec(), public_keys[0].clone(), 1)?;

    let proof = multi_sig_address
        .generate_proof(public_keys.to_vec())?
        .chain(|| (ErrorKind::InvalidInput, "Unable to generate merkle proof"))?;
    Ok(TxInWitness::TreeSig(private_key.schnorr_sign(tx)?, proof))
}

fn add_txout(tx: &mut CroTx, addr: &str, coin: u64) -> Result<()> {
    let txout = TxOut::new(
        ExtendedAddr::from_str(&addr).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to decode extended addr",
            )
        })?,
        Coin::new(coin).chain(|| (ErrorKind::DeserializationError, "Unable to decode coin"))?,
    );
    tx.tx.outputs.push(txout);
    Ok(())
}

/// add txout , this makes utxo
/// addr_string: which address in string?
/// coin: value to send in carson unit , 1 carson= 0.0000_0001 cro
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_tx_add_txout(
    tx_ptr: CroTxPtr,
    addr_string: *const c_char,
    coin: u64,
) -> CroResult {
    let mut tx = tx_ptr.as_mut().expect("get tx");
    let addr = get_string(addr_string);
    match add_txout(&mut tx, &addr, coin) {
        Ok(_) => CroResult::success(),
        Err(_) => CroResult::fail(),
    }
}

/// add txout with bytes
/// addr: which address in bytes
/// coin: value to send in carson unit , 1 carson= 0.0000_0001 cro
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_tx_add_txout_raw(
    tx_ptr: CroTxPtr,
    addr: [u8; 32],
    coin: u64,
) -> CroResult {
    let tx = tx_ptr.as_mut().expect("get tx");
    let txout = TxOut::new(
        ExtendedAddr::OrTree(addr),
        Coin::new(coin).expect("get coin in cro_tx_add_txout_raw"),
    );
    tx.tx.outputs.push(txout);
    CroResult::success()
}

/// destroy tx
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_destroy_tx(tx: CroTxPtr) -> CroResult {
    Box::from_raw(tx);
    CroResult::success()
}
