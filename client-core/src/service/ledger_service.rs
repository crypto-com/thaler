use client_common::Transaction;
use parity_scale_codec::Encode;
mod hid_service;
mod zemu_service;

pub use hid_service::{LedgerServiceHID, LedgerSignKeyHID};
pub use zemu_service::{LedgerServiceZemu, LedgerSignKeyZemu};

/// block to wait for the async result
#[macro_export]
macro_rules! sync {
    ($f:expr, $e: expr) => {{
        let mut run_time = Runtime::new().unwrap();
        run_time.block_on($f).chain(|| (ErrorKind::LedgerError, $e))
    }};
}

/// the header defined in `app/src/coin.h` of ledger crypto app, the size is `CRO_HEADER_SIZE` which is `2`
/// the first one is `CRO_TX_AUX_ENUM_ENCLAVE_TX` or `CRO_TX_AUX_ENUM_PUBLIC_TX`
/// the seconde one depends on the tx type, which is defined in `app/src/parser_txdef.h` of ledger crypto app
const CRO_TX_AUX_ENUM_ENCLAVE_TX: u8 = 0;
const CRO_TX_AUX_ENUM_PUBLIC_TX: u8 = 1;

const CRO_TX_AUX_PUBLIC_AUX_UNBOND_STAKE: u8 = 0;
const CRO_TX_AUX_PUBLIC_AUX_UNJAIL: u8 = 1;
const CRO_TX_AUX_PUBLIC_AUX_NODE_JOIN: u8 = 2;

const CRO_TX_AUX_ENCLAVE_TRANSFER_TX: u8 = 0;
const CRO_TX_AUX_ENCLAVE_DEPOSIT_STAKE: u8 = 1;
const CRO_TX_AUX_ENCLAVE_WITHDRAW_UNBOUNDED_STAKE: u8 = 2;

fn get_blob(tx: &Transaction) -> Vec<u8> {
    match tx {
        Transaction::UnbondStakeTransaction(tx) => {
            let mut encoded = tx.encode();
            let mut blob = vec![
                CRO_TX_AUX_ENUM_PUBLIC_TX,
                CRO_TX_AUX_PUBLIC_AUX_UNBOND_STAKE,
            ];
            blob.append(&mut encoded);
            blob
        }
        Transaction::UnjailTransaction(tx) => {
            let mut encoded = tx.encode();
            let mut blob = vec![CRO_TX_AUX_ENUM_PUBLIC_TX, CRO_TX_AUX_PUBLIC_AUX_UNJAIL];
            blob.append(&mut encoded);
            blob
        }
        Transaction::NodejoinTransaction(tx) => {
            let mut encoded = tx.encode();
            let mut blob = vec![CRO_TX_AUX_ENUM_PUBLIC_TX, CRO_TX_AUX_PUBLIC_AUX_NODE_JOIN];
            blob.append(&mut encoded);
            blob
        }
        Transaction::TransferTransaction(tx) => {
            let mut encoded = tx.encode();
            let mut blob = vec![CRO_TX_AUX_ENUM_ENCLAVE_TX, CRO_TX_AUX_ENCLAVE_TRANSFER_TX];
            blob.append(&mut encoded);
            blob
        }
        Transaction::DepositStakeTransaction(tx) => {
            let mut encoded = tx.encode();
            let mut blob = vec![CRO_TX_AUX_ENUM_ENCLAVE_TX, CRO_TX_AUX_ENCLAVE_DEPOSIT_STAKE];
            blob.append(&mut encoded);
            blob
        }
        Transaction::WithdrawUnbondedStakeTransaction(tx) => {
            let mut blob = vec![
                CRO_TX_AUX_ENUM_ENCLAVE_TX,
                CRO_TX_AUX_ENCLAVE_WITHDRAW_UNBOUNDED_STAKE,
            ];
            let mut encoded = tx.encode();
            blob.append(&mut encoded);
            blob
        }
    }
}
