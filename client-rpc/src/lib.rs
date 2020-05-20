use std::fmt::Debug;

pub mod rpc;

pub fn to_rpc_error<E: ToString + Debug>(error: E) -> jsonrpc_core::Error {
    log::error!("{:?}", error);
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: error.to_string(),
        data: None,
    }
}

pub fn rpc_error_from_string(error: String) -> jsonrpc_core::Error {
    log::error!("{}", error);
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: error,
        data: None,
    }
}
