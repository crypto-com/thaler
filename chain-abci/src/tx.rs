//! Implementation of deliver_tx/check_tx.

use parity_scale_codec::Decode;

use chain_core::state::account::StakedStateAddress;
use chain_core::tx::fee::Fee;
use chain_core::tx::TxAux;
use chain_storage::buffer::StoreStaking;
use chain_storage::Storage;
use chain_tx_validation::ChainInfo;

use crate::app::ChainNodeState;
use crate::enclave_bridge::EnclaveProxy;
use crate::staking_table::{NodeJoinError, UnbondError, UnjailError};
use crate::storage::{execute_enclave_tx, process_public_tx, verify_enclave_tx};

#[derive(thiserror::Error, Debug)]
pub enum PublicTxError {
    #[error("public tx wrong chain_hex_id")]
    WrongChainHexId,
    #[error("public tx unsupported version")]
    UnsupportedVersion,
    #[error("verify staking witness failed: {0}")]
    StakingWitnessVerify(#[from] secp256k1::Error),
    #[error("staking witness and address don't match")]
    StakingWitnessNotMatch,
    #[error("tx nonce don't match staking state")]
    IncorrectNonce,
    #[error("unjail tx process failed: {0}")]
    Unjail(#[from] UnjailError),
    #[error("node join tx process failed: {0}")]
    NodeJoin(#[from] NodeJoinError),
    #[error("unbond tx process failed: {0}")]
    Unbond(#[from] UnbondError),
}

#[derive(thiserror::Error, Debug)]
pub enum TxError {
    #[error("deserialize TxAux failed: {0}")]
    DeserializeTx(#[from] parity_scale_codec::Error),
    #[error("enclave tx validation failed: {0}")]
    Enclave(#[from] chain_tx_validation::Error),
    #[error("public tx process failed: {0}")]
    Public(#[from] PublicTxError),
}

// Implemented as function rather than method to fight the borrow checker
pub fn process_tx<T: EnclaveProxy>(
    tx_validator: &mut T,
    state: &mut ChainNodeState,
    chain_hex_id: u8,
    storage: &mut Storage,
    staking_store: &mut impl StoreStaking,
    mut txbytes: &[u8],
) -> Result<(TxAux, Fee, Option<StakedStateAddress>), TxError> {
    // TODO why panic
    let tx_len = txbytes.len();
    let min_fee = state
        .top_level
        .network_params
        .calculate_fee(tx_len)
        .expect("invalid fee policy");
    let txaux = TxAux::decode(&mut txbytes)?;
    let txid = txaux.tx_id();
    let extra_info = ChainInfo {
        min_fee_computed: min_fee,
        block_time: state.block_time,
        block_height: state.block_height,
        chain_hex_id,
        unbonding_period: state.top_level.network_params.get_unbonding_period(),
    };
    let (fee, maccount) = match &txaux {
        TxAux::EnclaveTx(tx) => {
            let action =
                verify_enclave_tx(tx_validator, &*storage, staking_store, &tx, extra_info)?;
            // execute the action
            let maccount = execute_enclave_tx(
                storage,
                staking_store,
                &mut state.staking_table,
                state.block_time,
                &txid,
                &action,
            );
            (action.fee(), maccount)
        }
        _ => process_public_tx(staking_store, &mut state.staking_table, &extra_info, &txaux)?,
    };
    Ok((txaux, fee, maccount))
}
