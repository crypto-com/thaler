use super::ChainNodeApp;
use crate::storage::tx::{verify, ChainInfo};
use abci::*;
use chain_core::state::account::Account;
use chain_core::tx::fee::{Fee, FeeAlgorithm};
use chain_core::tx::TxAux;
use parity_codec::Decode;

/// Wrapper to astract over CheckTx and DeliverTx requests
pub trait RequestWithTx {
    fn tx(&self) -> &[u8];
}

impl RequestWithTx for RequestCheckTx {
    fn tx(&self) -> &[u8] {
        &self.tx[..]
    }
}

impl RequestWithTx for RequestDeliverTx {
    fn tx(&self) -> &[u8] {
        &self.tx[..]
    }
}

/// Wrapper to astract over CheckTx and DeliverTx responses
pub trait ResponseWithCodeAndLog {
    fn set_code(&mut self, _: u32);
    fn add_log(&mut self, _: &str);
}

impl ResponseWithCodeAndLog for ResponseCheckTx {
    fn set_code(&mut self, new_code: u32) {
        self.code = new_code;
    }

    fn add_log(&mut self, entry: &str) {
        self.log += entry;
    }
}

impl ResponseWithCodeAndLog for ResponseDeliverTx {
    fn set_code(&mut self, new_code: u32) {
        self.code = new_code;
    }

    fn add_log(&mut self, entry: &str) {
        self.log += entry;
    }
}

impl ChainNodeApp {
    /// Gets CheckTx or DeliverTx requests, tries to parse its data into TxAux and validate that TxAux.
    /// Returns Some(parsed txaux) if OK, or None if some problems (and sets log + error code in the passed in response).
    pub fn validate_tx_req(
        &self,
        _req: &dyn RequestWithTx,
        resp: &mut dyn ResponseWithCodeAndLog,
    ) -> Option<(TxAux, (Fee, Option<Account>))> {
        let data = Vec::from(_req.tx());
        let dtx = TxAux::decode(&mut data.as_slice());
        match dtx {
            None => {
                resp.set_code(1);
                resp.add_log("failed to deserialize tx");
                None
            }
            Some(txaux) => {
                let state = self.last_state.as_ref().expect("the app state is expected");
                let min_fee = state
                    .fee_policy
                    .calculate_fee(_req.tx().len())
                    .expect("invalid fee policy");
                let fee_paid = verify(
                    &txaux,
                    ChainInfo {
                        min_fee_computed: min_fee,
                        chain_hex_id: self.chain_hex_id,
                        previous_block_time: state.block_time,
                        last_account_root_hash: self.uncommitted_account_root_hash,
                        unbonding_period: state.unbonding_period,
                    },
                    self.storage.db.clone(),
                    &self.accounts,
                );
                if fee_paid.is_ok() {
                    resp.set_code(0);
                    Some((txaux, fee_paid.unwrap()))
                } else {
                    resp.set_code(1);
                    resp.add_log(&format!("verification failed: {}", fee_paid.unwrap_err()));
                    None
                }
            }
        }
    }
}
