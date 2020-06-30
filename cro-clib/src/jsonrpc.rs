use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use std::sync::Arc;
use std::sync::Mutex;

use client_common::Result;
use client_core::wallet::syncer::SyncerOptions;
use client_rpc_core::{
    rpc::sync_rpc::{CBindingCallback, CBindingCore},
    RpcHandler,
};

use crate::types::get_string;
use crate::types::CroResult;
use crate::types::ProgressCallback;
use crate::types::{CroJsonRpc, CroJsonRpcPtr};

#[derive(Clone)]
struct CBindingData {
    progress_callback: ProgressCallback,
    // SAFETY-WARNING, DO NOT use this inside rust, just pass back to c-side
    user_data: u64,
}

impl CBindingCallback for CBindingData {
    // SAFETY-WARNING, DO NOT use this inside rust, just pass back to c-side
    fn set_user(&mut self, user: u64) {
        self.user_data = user;
    }
    // SAFETY-WARNING, DO NOT use this inside rust, just pass back to c-side
    fn get_user(&self) -> u64 {
        self.user_data
    }

    fn progress(&mut self, current: u64, start: u64, end: u64) -> i32 {
        let back = &self.progress_callback;
        (back)(
            current,
            start,
            end,
            // SAFETY-WARNING, DO NOT use this inside rust, just pass back to c-side
            self.user_data as *const std::ffi::c_void,
        )
    }
}

/// # Safety
///
/// Should not be called with null pointers.
///
/// c example:
///
/// ```c
/// char buf[BUFSIZE];
/// const char* req = "{\"jsonrpc\": \"2.0\", \"method\": \"wallet_list\", \"params\": [], \"id\": 1}";
/// int retcode = cro_jsonrpc_call("./data", "ws://...", 0xab, req, buf, sizeof(buf));
/// if (retcode == 0) {
///     printf("response: %s\n", buf);
/// } else {
///     printf("error: %s\n", buf);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn cro_jsonrpc_call(
    storage_dir: *const c_char,
    websocket_url: *const c_char,
    network_id: u8,
    request: *const c_char,
    buf: *mut c_char,
    buf_size: usize,
    progress_callback: Option<ProgressCallback>,
    user_data: *const std::ffi::c_void,
) -> CroResult {
    let res = create_rpc(
        storage_dir,
        websocket_url,
        network_id,
        progress_callback,
        user_data,
        false,
    )
    .map(|rpc| {
        let json_request = get_string(request);
        rpc.handler.handle(&json_request).unwrap_or_default()
    });
    match res {
        Err(e) => {
            libc::strncpy(
                buf,
                CString::new(e.to_string()).unwrap().into_raw(),
                buf_size,
            );
            CroResult::fail()
        }
        Ok(s) => {
            libc::strncpy(buf, CString::new(s).unwrap().into_raw(), buf_size);
            CroResult::success()
        }
    }
}

// this function is dummy function to export function pointer
#[no_mangle]
pub extern "C" fn cro_jsonrpc_call_dummy(_progress_callback: ProgressCallback) {}

/// mock mode, only use for testing
///
/// # Safety
///
/// Should not be called with null pointers.
#[cfg(debug_assertions)]
#[no_mangle]
pub unsafe extern "C" fn cro_jsonrpc_call_mock(
    storage_dir: *const c_char,
    websocket_url: *const c_char,
    network_id: u8,
    request: *const c_char,
    buf: *mut c_char,
    buf_size: usize,
    progress_callback: Option<ProgressCallback>, /* for callback info */
    user_data: *const std::ffi::c_void,
) -> CroResult {
    let res = create_rpc(
        storage_dir,
        websocket_url,
        network_id,
        progress_callback,
        user_data,
        true,
    )
    .map(|rpc| {
        let json_request = get_string(request);
        rpc.handler.handle(&json_request).unwrap_or_default()
    });
    match res {
        Err(e) => {
            libc::strncpy(
                buf,
                CString::new(e.to_string()).unwrap().into_raw(),
                buf_size,
            );
            CroResult::fail()
        }
        Ok(s) => {
            libc::strncpy(buf, CString::new(s).unwrap().into_raw(), buf_size);
            CroResult::success()
        }
    }
}

/// create json-rpc context
/// rpc_out: null pointer which will be written
/// example c-code)
///  CroJsonRpcPtr rpc= NULL;
///  cro_create_jsonrpc(&rpc, ".storage", "ws://localhost:26657/websocket", 0xab, &progress);
/// storage_dir: ".storage"
/// websocket_url:  "ws://localhost:26657/websocket"
/// network: network-id  ex) 0xab
/// progress_callback: callback function which user codes
/// example c-code)
/// int32_t  progress(float rate)
/// {
///    printf("progress %f\n", rate);
/// }
/// you can give this callback like below
/// CroResult retcode = cro_jsonrpc_call("./.storage", "ws://localhost:26657/websocket", 0xab, req, buf, sizeof(buf), &progress);
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn cro_create_jsonrpc(
    rpc_out: *mut CroJsonRpcPtr,
    storage_dir_user: *const c_char,
    websocket_url_user: *const c_char,
    network_id: u8,
    progress_callback: Option<ProgressCallback>,
) -> CroResult {
    let mrpc = create_rpc(
        storage_dir_user,
        websocket_url_user,
        network_id,
        progress_callback,
        ptr::null(),
        false,
    );
    match mrpc {
        Ok(rpc) => {
            let rpc_box = Box::new(rpc);
            ptr::write(rpc_out, Box::into_raw(rpc_box));
            CroResult::success()
        }
        _ => CroResult::fail(),
    }
}

/// mock mode, only use for testing
///
/// # Safety
///
/// Should not be called with null pointers.
#[cfg(debug_assertions)]
#[no_mangle]
pub unsafe extern "C" fn cro_create_mock_jsonrpc(
    rpc_out: *mut CroJsonRpcPtr,
    storage_dir_user: *const c_char,
    websocket_url_user: *const c_char,
    network_id: u8,
    progress_callback: Option<ProgressCallback>,
) -> CroResult {
    let mrpc = create_rpc(
        storage_dir_user,
        websocket_url_user,
        network_id,
        progress_callback,
        ptr::null(),
        true,
    );
    match mrpc {
        Ok(rpc) => {
            let rpc_box = Box::new(rpc);
            ptr::write(rpc_out, Box::into_raw(rpc_box));
            CroResult::success()
        }
        _ => CroResult::fail(),
    }
}

/// request: json rpc request
/// example c code) const char* req = "{\"jsonrpc\": \"2.0\", \"method\": \"wallet_list\", \"params\": [], \"id\": 1}";
/// buf: minimum 500 bytes
/// buf_size: size of buf in bytes
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn cro_run_jsonrpc(
    rpc_ptr: CroJsonRpcPtr,
    request: *const c_char,
    buf: *mut c_char,
    buf_size: usize,
    user_data: *const std::ffi::c_void,
) -> CroResult {
    if rpc_ptr.is_null() {
        return CroResult::fail();
    }
    let rpc = rpc_ptr.as_mut().expect("get wallet");
    let json_request = get_string(request);

    if let Some(binding) = &(*rpc).binding {
        let mut user = binding.data.lock().expect("get cbinding callback");
        user.set_user(user_data as u64);
    }

    let s = rpc.handler.handle(&json_request).unwrap_or_default();
    libc::strncpy(buf, CString::new(s).unwrap().into_raw(), buf_size);
    CroResult::success()
}

/// destroy json-rpc context
/// rpc: containing pointer to free
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn cro_destroy_jsonrpc(rpc: CroJsonRpcPtr) -> CroResult {
    Box::from_raw(rpc);
    CroResult::success()
}

unsafe fn create_rpc(
    storage_dir: *const c_char,
    websocket_url: *const c_char,
    network_id: u8,
    progress_callback: Option<ProgressCallback>,
    user_data: *const std::ffi::c_void,
    _mock: bool,
) -> Result<CroJsonRpc> {
    let storage_dir = get_string(storage_dir);
    let websocket_url = get_string(websocket_url);
    let cbindingcallback = progress_callback.map(|progress_callback| CBindingCore {
        data: Arc::new(Mutex::new(CBindingData {
            progress_callback,
            user_data: user_data as u64,
        })),
    });

    let options = SyncerOptions {
        enable_fast_forward: false,
        enable_address_recovery: true,
        batch_size: 50,
        block_height_ensure: 50,
    };
    let handler = RpcHandler::new(
        &storage_dir,
        &websocket_url,
        network_id,
        options,
        cbindingcallback.clone(),
    )?;

    Ok(CroJsonRpc {
        handler,
        binding: cbindingcallback,
    })
}
