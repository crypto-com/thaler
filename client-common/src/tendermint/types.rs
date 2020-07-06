//! Structures used in Tendermint RPC
mod block_results;

use parity_scale_codec::Decode;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::{ErrorKind, Result, ResultExt, Transaction};
use chain_core::init::config::InitConfig;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::LinearFee;
use chain_core::tx::{TxAux, TxEnclaveAux, TxPublicAux};

pub use self::block_results::BlockResults;
pub use tendermint::{
    abci, abci::transaction::Data, abci::Code, block::Header, block::Height, Block,
    Genesis as GenericGenesis, Hash, Time,
};
pub use tendermint_rpc::endpoint::{
    abci_query::AbciQuery, abci_query::Response as AbciQueryResponse,
    block::Response as BlockResponse, block_results::Response as BlockResultsResponse, broadcast,
    broadcast::tx_sync::Response as BroadcastTxResponse, commit::Response as CommitResponse,
    status, status::Response as StatusResponse, validators::Response as ValidatorsResponse,
};

/// crypto-com instantiated genesis type
pub type Genesis = GenericGenesis<Option<InitConfig>>;

/// crypto-com instantiated genesis type
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GenesisResponse {
    /// Genesis data
    pub genesis: Genesis,
}

/// crypto-chain specific methods.
pub trait BlockExt {
    /// Returns un-encrypted staking(deposit/unbound) transactions in a block
    /// (this may also contain invalid transactions)
    fn staking_transactions(&self) -> Result<Vec<Transaction>>;

    /// Returns ids of transactions whose main content is only available in enclaves (Transfer, Withdraw)
    fn enclave_transaction_ids(&self) -> Result<Vec<TxId>>;
}

impl BlockExt for Block {
    fn staking_transactions(&self) -> Result<Vec<Transaction>> {
        self.data
            .iter()
            .map(|raw| -> Result<TxAux> {
                TxAux::decode(&mut raw.clone().into_vec().as_slice()).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to decode transactions from bytes in a block",
                    )
                })
            })
            .filter_map(|tx_aux_result| match tx_aux_result {
                Err(e) => Some(Err(e)),
                Ok(tx_aux) => match tx_aux {
                    TxAux::EnclaveTx(TxEnclaveAux::DepositStakeTx { tx, .. }) => {
                        Some(Ok(Transaction::DepositStakeTransaction(tx)))
                    }
                    TxAux::PublicTx(TxPublicAux::UnbondStakeTx(tx, _)) => {
                        Some(Ok(Transaction::UnbondStakeTransaction(tx)))
                    }
                    _ => None,
                },
            })
            .collect::<Result<Vec<Transaction>>>()
    }
    fn enclave_transaction_ids(&self) -> Result<Vec<TxId>> {
        self.data
            .iter()
            .map(|raw| -> Result<TxAux> {
                TxAux::decode(&mut raw.clone().into_vec().as_slice()).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to decode transactions from bytes in a block",
                    )
                })
            })
            .filter_map(|tx_aux_result| match tx_aux_result {
                Err(e) => Some(Err(e)),
                Ok(tx_aux) => match tx_aux {
                    TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx { .. }) => {
                        Some(Ok(tx_aux.tx_id()))
                    }
                    TxAux::EnclaveTx(TxEnclaveAux::TransferTx { .. }) => Some(Ok(tx_aux.tx_id())),
                    _ => None,
                },
            })
            .collect::<Result<Vec<TxId>>>()
    }
}

/// crypto-chain specific methods.
pub trait GenesisExt {
    /// get fee policy
    fn fee_policy(&self) -> LinearFee;
    /// get light client trusting period
    fn trusting_period(&self) -> Duration;
}

impl GenesisExt for Genesis {
    fn fee_policy(&self) -> LinearFee {
        self.app_state
            .as_ref()
            .expect("parsed app state")
            .network_params
            .initial_fee_policy
    }

    fn trusting_period(&self) -> Duration {
        self.consensus_params.evidence.max_age_duration.into()
    }
}

/// crypto-chain specific methods.
pub trait AbciQueryExt {
    /// get query result
    fn bytes(&self) -> Vec<u8>;
}

impl AbciQueryExt for AbciQuery {
    fn bytes(&self) -> Vec<u8> {
        self.value.clone()
    }
}
