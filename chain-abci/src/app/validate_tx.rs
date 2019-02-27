use super::ChainNodeApp;
use crate::storage::tx::verify;
use abci::*;
use chain_core::tx::TxAux;
use serde_cbor::{error, from_slice};

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
    ) -> Option<TxAux> {
        let dtx: error::Result<TxAux> = from_slice(_req.tx());
        match dtx {
            Err(e) => {
                resp.set_code(1);
                resp.add_log(&format!("failed to deserialize tx: {}", e));
                None
            }
            Ok(txaux) => {
                let v = verify(
                    &txaux,
                    self.chain_hex_id,
                    self.storage.db.clone(),
                    self.block_time.expect("Last block's timestamp is expected"),
                );
                if v.is_ok() {
                    resp.set_code(0);
                } else {
                    resp.set_code(1);
                    resp.add_log(&format!("verification failed: {}", v.unwrap_err()));
                }
                Some(txaux)
            }
        }
    }
}
