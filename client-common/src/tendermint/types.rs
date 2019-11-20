//! Structures used in Tendermint RPC
mod block_results;

use base64::decode;
use parity_scale_codec::Decode;
use serde::{Deserialize, Serialize};

use crate::{ErrorKind, Result, ResultExt, Transaction};
use chain_core::init::config::InitConfig;
use chain_core::tx::fee::LinearFee;
use chain_core::tx::{TxAux, TxEnclaveAux};

pub use self::block_results::*;
pub use tendermint::rpc::endpoint::{
    abci_query::AbciQuery, abci_query::Response as AbciQueryResponse,
    block::Response as BlockResponse, broadcast::tx_sync::Response as BroadcastTxResponse,
    commit::Response as CommitResponse, status::Response as Status,
    validators::Response as ValidatorsResponse,
};
pub use tendermint::rpc::endpoint::{broadcast, status};
pub use tendermint::{
    abci, abci::transaction::Data, abci::Code, block::Header, block::Height, Block,
    Genesis as GenericGenesis, Hash, Time,
};

/// crypto-com instantiated genesis type
pub type Genesis = GenericGenesis<InitConfig>;

/// crypto-com instantiated genesis type
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GenesisResponse {
    /// Genesis data
    pub genesis: Genesis,
}

/// crypto-chain specific methods.
pub trait BlockExt {
    /// Returns un-encrypted transactions in a block (this may also contain invalid transactions)
    fn unencrypted_transactions(&self) -> Result<Vec<Transaction>>;
}

impl BlockExt for Block {
    /// NOTE: Un-encrypted transactions only contain deposit stake and unbond stake transactions
    fn unencrypted_transactions(&self) -> Result<Vec<Transaction>> {
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
                    TxAux::UnbondStakeTx(tx, _) => {
                        Some(Ok(Transaction::UnbondStakeTransaction(tx)))
                    }
                    _ => None,
                },
            })
            .collect::<Result<Vec<Transaction>>>()
    }
}

/// crypto-chain specific methods.
pub trait GenesisExt {
    /// get fee policy
    fn fee_policy(&self) -> LinearFee;
}

impl GenesisExt for Genesis {
    fn fee_policy(&self) -> LinearFee {
        self.app_state.network_params.initial_fee_policy
    }
}

/// crypto-chain specific methods.
pub trait AbciQueryExt {
    /// decode query result with base64
    fn bytes(&self) -> Result<Vec<u8>>;
}

impl AbciQueryExt for AbciQuery {
    fn bytes(&self) -> Result<Vec<u8>> {
        match &self.value {
            None => Ok(vec![]),
            Some(value) => Ok(decode(value).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to decode base64 bytes on query result",
                )
            })?),
        }
    }
}
