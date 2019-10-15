use chain_core::tx::data::TxId;
use enclave_protocol::{EnclaveRequest, EnclaveResponse, FLAGS};
use log::{debug, error, trace};
use parity_scale_codec::{Decode, Encode};
use sgx_types::*;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::IntoRawFd;
use std::sync::Once;
use zmq::{Context, Socket, REQ};

static ZMQ_CONNECTION_INIT: Once = Once::new();

mod zmq_connection {
    pub static mut CONNECTION_STR: String = String::new();
}

/// To set the ZMQ connection string once on the startup
pub fn init_connection(connection_str: &str) {
    unsafe {
        ZMQ_CONNECTION_INIT.call_once(|| {
            zmq_connection::CONNECTION_STR = connection_str.to_string();
        })
    }
}

fn get_connection_str() -> &'static str {
    unsafe { &zmq_connection::CONNECTION_STR }
}

fn init_socket() -> Socket {
    let ctx = Context::new();
    let socket = ctx.socket(REQ).expect("failed to init zmq context");
    socket
        .connect(get_connection_str())
        .expect("failed to connect to the tx validation enclave zmq");
    socket
}

thread_local! {
    pub static ZMQ_SOCKET: Socket = init_socket();
}

/// Untrusted function called from the enclave -- sends a ZMQ message to
/// the transaction validation enclave that handles storage
/// and passes back the reply
#[no_mangle]
pub extern "C" fn ocall_get_txs(
    txids: *const u8,
    txids_len: u32,
    txs: *mut u8,
    txs_len: u32,
) -> sgx_status_t {
    let mut txids_slice = unsafe { std::slice::from_raw_parts(txids, txids_len as usize) };
    // TODO: directly construct EnclaveRequest in the enclave
    let txids_i: Result<Vec<TxId>, parity_scale_codec::Error> = Decode::decode(&mut txids_slice);
    if let Ok(txids) = txids_i {
        let request = EnclaveRequest::GetSealedTxData { txids };
        let req = request.encode();
        let r = ZMQ_SOCKET.with(|socket| {
            let send_r = socket.send(req, FLAGS);
            if send_r.is_err() {
                error!("failed to send a request for obtaining sealed data");
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
            // TODO: pass back response directly
            if let Ok(msg) = socket.recv_bytes(FLAGS) {
                match EnclaveResponse::decode(&mut msg.as_slice()) {
                    Ok(EnclaveResponse::GetSealedTxData(Some(data))) => {
                        let txs_enc = data.encode();
                        if txs_enc.len() > (txs_len as usize) {
                            error!("Not enough allocated space to return the sealed tx data");
                            return sgx_status_t::SGX_ERROR_UNEXPECTED;
                        } else {
                            unsafe {
                                std::ptr::copy(txs_enc.as_ptr(), txs, txs_enc.len());
                            }
                            return sgx_status_t::SGX_SUCCESS;
                        }
                    }
                    _ => {
                        error!("failed to decode a response for obtaining sealed data");
                        return sgx_status_t::SGX_ERROR_UNEXPECTED;
                    }
                }
            } else {
                error!("failed to receive a response for obtaining sealed data");
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        });
        r
    } else {
        error!("failed to decode transaction ids");
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }
}

/// Untrusted function called from the enclave -- sends a ZMQ message to
/// the transaction validation enclave that encrypt the sealed payload
#[no_mangle]
pub extern "C" fn ocall_encrypt_request(
    request: *const u8,
    request_len: u32,
    result: *mut u8,
    result_len: u32,
) -> sgx_status_t {
    let request_slice = unsafe { std::slice::from_raw_parts(request, request_len as usize) };
    ZMQ_SOCKET.with(|socket| {
        let send_r = socket.send(request_slice, FLAGS);
        if send_r.is_err() {
            error!("failed to send a request for obtaining obfuscated tx");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
        if let Ok(msg) = socket.recv_bytes(FLAGS) {
            if msg.len() > (result_len as usize) {
                error!("Not enough allocated space to return the sealed tx data");
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            } else {
                unsafe {
                    std::ptr::copy(msg.as_ptr(), result, msg.len());
                }
                return sgx_status_t::SGX_SUCCESS;
            }
        } else {
            error!("failed to send a request for obtaining obfuscated tx");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    })
}

extern "C" {
    /// the enclave main function / routine (just gets raw file descriptor of the connection client TCP socket)
    pub fn run_server(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        socket_fd: c_int,
    ) -> sgx_status_t;
}

/// Untrusted function called from the enclave -- requests quote (initialization) from Intel SDK's AESM
#[no_mangle]
pub extern "C" fn ocall_sgx_init_quote(
    ret_ti: *mut sgx_target_info_t,
    ret_gid: *mut sgx_epid_group_id_t,
) -> sgx_status_t {
    trace!("Entering ocall_sgx_init_quote");
    unsafe { sgx_init_quote(ret_ti, ret_gid) }
}

/// Untrusted function called from the enclave -- gets the IAS API key set as an environment variable
#[no_mangle]
pub extern "C" fn ocall_get_ias_key(ias_key: *mut u8, ias_key_len: u32) -> sgx_status_t {
    let ias_key_org = std::env::var("IAS_API_KEY").expect("IAS key not set");
    if ias_key_org.len() != (ias_key_len as usize) {
        error!("invalid ias key length");
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }
    unsafe {
        std::ptr::copy(ias_key_org.as_ptr(), ias_key, ias_key_len as usize);
    }

    sgx_status_t::SGX_SUCCESS
}

fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}

/// Untrusted function called from the enclave -- gets the TCP socket of Intel Attestation Service
#[no_mangle]
pub extern "C" fn ocall_get_ias_socket(ret_fd: *mut c_int) -> sgx_status_t {
    let port = 443;
    let hostname = "api.trustedservices.intel.com";
    let addr = lookup_ipv4(hostname, port);
    let sock = TcpStream::connect(&addr).expect("[-] Connect tls server failed!");

    unsafe {
        *ret_fd = sock.into_raw_fd();
    }

    sgx_status_t::SGX_SUCCESS
}

fn decode_hex_digit(digit: char) -> u8 {
    match digit {
        '0'..='9' => digit as u8 - '0' as u8,
        'a'..='f' => digit as u8 - 'a' as u8 + 10,
        'A'..='F' => digit as u8 - 'A' as u8 + 10,
        _ => panic!(),
    }
}

fn get_spid() -> sgx_spid_t {
    let mut spid = sgx_spid_t::default();
    let spid_hex = std::env::var("SPID").expect("SPID not set");
    let hex = spid_hex.trim();

    if hex.len() != 32 {
        panic!("Input spid len ({}) is incorrect!", hex.len());
    }

    let decoded_vec = decode_hex(hex);

    spid.id.copy_from_slice(&decoded_vec[..16]);

    spid
}

fn decode_hex(hex: &str) -> Vec<u8> {
    let mut r: Vec<u8> = Vec::new();
    let mut chars = hex.chars().enumerate();
    loop {
        let (pos, first) = match chars.next() {
            None => break,
            Some(elt) => elt,
        };
        if first == ' ' {
            continue;
        }
        let (_, second) = match chars.next() {
            None => panic!("pos = {}d", pos),
            Some(elt) => elt,
        };
        r.push((decode_hex_digit(first) << 4) | decode_hex_digit(second));
    }
    r
}

/// Untrusted function called from the enclave -- requests quote (gets the payload) from Intel SDK's AESM
#[no_mangle]
pub extern "C" fn ocall_get_quote(
    p_sigrl: *const u8,
    sigrl_len: u32,
    p_report: *const sgx_report_t,
    quote_type: sgx_quote_sign_type_t,
    p_nonce: *const sgx_quote_nonce_t,
    p_qe_report: *mut sgx_report_t,
    p_quote: *mut u8,
    _maxlen: u32,
    p_quote_len: *mut u32,
) -> sgx_status_t {
    trace!("Entering ocall_get_quote");

    let mut real_quote_len: u32 = 0;

    let ret = unsafe { sgx_calc_quote_size(p_sigrl, sigrl_len, &mut real_quote_len as *mut u32) };

    if ret != sgx_status_t::SGX_SUCCESS {
        error!("sgx_calc_quote_size returned {}", ret);
        return ret;
    }

    debug!("quote size = {}", real_quote_len);
    unsafe {
        *p_quote_len = real_quote_len;
    }

    let spid: sgx_spid_t = get_spid();

    let p_spid = &spid as *const sgx_spid_t;

    let ret = unsafe {
        sgx_get_quote(
            p_report,
            quote_type,
            p_spid,
            p_nonce,
            p_sigrl,
            sigrl_len,
            p_qe_report,
            p_quote as *mut sgx_quote_t,
            real_quote_len,
        )
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        error!("sgx_calc_quote_size returned {}", ret);
        return ret;
    }

    debug!("sgx_calc_quote_size returned {}", ret);
    ret
}

/// Untrusted function called from the enclave -- checks the platform blob retrieved from IAS
#[no_mangle]
pub extern "C" fn ocall_get_update_info(
    platform_blob: *const sgx_platform_info_t,
    enclave_trusted: i32,
    update_info: *mut sgx_update_info_bit_t,
) -> sgx_status_t {
    unsafe { sgx_report_attestation_status(platform_blob, enclave_trusted, update_info) }
}
