use std::sync::{Arc, Mutex};

use enclave_protocol::{EnclaveRequest, EnclaveResponse};
use tx_validation_app::TxValidationApp;

use super::EnclaveProxy;

pub struct EnclaveAppProxy {
    app: Arc<Mutex<TxValidationApp>>,
}

impl EnclaveAppProxy {
    pub fn new(app: Arc<Mutex<TxValidationApp>>) -> EnclaveAppProxy {
        EnclaveAppProxy { app }
    }
}

impl EnclaveProxy for EnclaveAppProxy {
    fn process_request(&mut self, request: EnclaveRequest) -> EnclaveResponse {
        self.app.lock().unwrap().execute(request)
    }
}
