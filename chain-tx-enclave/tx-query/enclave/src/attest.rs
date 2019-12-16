//! # Remote Attestation utilities
//! portions of code adapted from https://github.com/mesalock-linux/mesatee (MesaTEE)
//! Copyright (c) 2019, MesaTEE Authors (licensed under the Apache License, Version 2.0)
//! Modifications Copyright (c) 2019, Foris Limited (licensed under the Apache License, Version 2.0)

use sgx_rand::*;
use sgx_tcrypto::*;
use sgx_tse::*;
use sgx_types::*;

use crate::cert::CertKeyPair;
use core::hash::{Hash, Hasher};
use lazy_static::lazy_static;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::prelude::v1::*;
use std::ptr;
use std::str;
use std::string::String;
use std::sync::Arc;
use std::sync::SgxRwLock;
use std::time::SystemTime;
use std::untrusted::time::SystemTimeEx;
use std::vec::Vec;
use zeroize::Zeroize;

pub const IAS_HOSTNAME: &'static str = "api.trustedservices.intel.com";
#[cfg(not(feature = "production"))]
pub const API_SUFFIX: &'static str = "/sgx/dev";
#[cfg(feature = "production")]
pub const API_SUFFIX: &'static str = "/sgx";
pub const SIGRL_SUFFIX: &'static str = "/attestation/v3/sigrl/";
pub const REPORT_SUFFIX: &'static str = "/attestation/v3/report";

extern "C" {
    pub fn ocall_sgx_init_quote(
        ret_val: *mut sgx_status_t,
        ret_ti: *mut sgx_target_info_t,
        ret_gid: *mut sgx_epid_group_id_t,
    ) -> sgx_status_t;
    pub fn ocall_get_ias_key(
        ret_val: *mut sgx_status_t,
        ias_key: *mut u8,
        ias_key_len: u32,
    ) -> sgx_status_t;
    pub fn ocall_get_ias_socket(ret_val: *mut sgx_status_t, ret_fd: *mut i32) -> sgx_status_t;
    pub fn ocall_get_quote(
        ret_val: *mut sgx_status_t,
        p_sigrl: *const u8,
        sigrl_len: u32,
        p_report: *const sgx_report_t,
        quote_type: sgx_quote_sign_type_t,
        p_nonce: *const sgx_quote_nonce_t,
        p_qe_report: *mut sgx_report_t,
        p_quote: *mut u8,
        maxlen: u32,
        p_quote_len: *mut u32,
    ) -> sgx_status_t;
}

struct RACache {
    cert_key: CertKeyPair,
    gen_time: SystemTime,
}

lazy_static! {
    static ref RACACHE: SgxRwLock<RACache> = {
        SgxRwLock::new(RACache {
            cert_key: CertKeyPair {
                cert: Vec::<u8>::new(),
                private_key: crate::cert::PrivateKey::new(Vec::<u8>::new()),
            },
            gen_time: SystemTime::UNIX_EPOCH,
        })
    };

    static ref IAS_CLIENT_CONFIG: Arc<rustls::ClientConfig> = {
        let mut config = rustls::ClientConfig::new();

        // We trust known CA
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        Arc::new(config)
    };

    static ref SVRCONFIGCACHE: SgxRwLock<HashMap<u64, Arc<rustls::ServerConfig>>> =
        { SgxRwLock::new(HashMap::new()) };
}

fn is_tls_config_updated(gen_time: &SystemTime) -> bool {
    let dur = SystemTime::now().duration_since(*gen_time);
    // max one day diff
    let max_allowed_diff = std::time::Duration::from_secs(86400u64);
    dur.is_ok() && dur.unwrap() < max_allowed_diff
}

#[derive(Debug)]
enum RAError {
    ParseError,
    RAInternalError,
    MissingValue,
    CommunicationError,
    APIKeyError,
    CertGeneration,
}

fn percent_decode(orig: String) -> Result<String, RAError> {
    let v: Vec<&str> = orig.split('%').collect();
    let mut ret = String::new();
    ret.push_str(v[0]);
    if v.len() > 1 {
        for s in v[1..].iter() {
            let digit = u8::from_str_radix(&s[0..2], 16).map_err(|_| RAError::ParseError)?;
            ret.push(digit as char);
            ret.push_str(&s[2..]);
        }
    }
    Ok(ret)
}

fn sanitize_http_response(respp: &httparse::Response) -> Result<(), RAError> {
    if let Some(code) = respp.code {
        if code != 200 {
            Err(RAError::RAInternalError)
        } else {
            Ok(())
        }
    } else {
        Err(RAError::RAInternalError)
    }
}

struct AttnReport {
    pub report: String,
    pub signature: String,
    pub certificate: String,
}

fn parse_response_attn_report(resp: &[u8]) -> Result<AttnReport, RAError> {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);

    sanitize_http_response(&respp)?;

    let mut sig = String::new();
    let mut sig_cert = String::new();
    let mut attn_report = String::new();

    for header in respp.headers {
        match header.name {
            "Content-Length" => {
                let len_str =
                    String::from_utf8(header.value.to_vec()).map_err(|_| RAError::ParseError)?;
                let len_num = len_str.parse::<u32>().map_err(|_| RAError::ParseError)?;
                if len_num != 0 {
                    let status = result.map_err(|_| RAError::ParseError)?;
                    let header_len = match status {
                        httparse::Status::Complete(l) => l,
                        _ => {
                            return Err(RAError::ParseError);
                        }
                    };
                    let resp_body = &resp[header_len..];
                    attn_report = str::from_utf8(resp_body)
                        .map_err(|_| RAError::ParseError)?
                        .to_string();
                    // println!("Attestation report: {}", attn_report);
                }
            }
            "X-IASReport-Signature" => {
                sig = str::from_utf8(header.value)
                    .map_err(|_| RAError::ParseError)?
                    .to_string()
            }
            "X-IASReport-Signing-Certificate" => {
                let mut cert = str::from_utf8(header.value)
                    .map_err(|_| RAError::ParseError)?
                    .to_string();
                // Remove %0A from cert, and only obtain the signing cert
                cert = cert.replace("%0A", "");
                // We should get two concatenated PEM files at this step
                cert = percent_decode(cert)?;
                let cert_content: Vec<&str> = cert.split("-----").collect();
                // expected number of parts
                if cert_content.len() != 9 {
                    return Err(RAError::MissingValue);
                } else {
                    sig_cert = cert_content[2].to_string();
                }
            }
            _ => (),
        }
    }

    Ok(AttnReport {
        report: attn_report,
        signature: sig,
        certificate: sig_cert,
    })
}

fn parse_response_sigrl(resp: &[u8]) -> Result<Vec<u8>, RAError> {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);

    sanitize_http_response(&respp)?;
    let header = respp
        .headers
        .iter()
        .find(|&&header| header.name == "Content-Length")
        .ok_or(RAError::ParseError)?;
    let len_str = String::from_utf8(header.value.to_vec()).map_err(|_| RAError::ParseError)?;
    let len_num = len_str.parse::<u32>().map_err(|_| RAError::ParseError)?;
    if len_num == 0 {
        Ok(Vec::new())
    } else {
        let status = result.map_err(|_| RAError::ParseError)?;
        let header_len = match status {
            httparse::Status::Complete(l) => l,
            _ => {
                return Err(RAError::ParseError);
            }
        };
        let resp_body = &resp[header_len..];
        let base64_body = str::from_utf8(resp_body).map_err(|_| RAError::ParseError)?;
        base64::decode(base64_body).map_err(|_| RAError::ParseError)
    }
}

fn get_sigrl_from_intel(ias_key: &str, fd: c_int, gid: u32) -> Result<Vec<u8>, RAError> {
    // println!("get_sigrl_from_intel fd = {:?}", fd);

    let req = format!("GET {}{}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
                        API_SUFFIX,
                        SIGRL_SUFFIX,
                        gid,
                        IAS_HOSTNAME,
                        ias_key);

    // println!("{}", req);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(IAS_HOSTNAME)
        .map_err(|_| RAError::CommunicationError)?;
    let mut sess = rustls::ClientSession::new(&IAS_CLIENT_CONFIG, dns_name);
    let mut sock = TcpStream::new(fd).map_err(|_| RAError::CommunicationError)?;
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    tls.write(req.as_bytes())
        .map_err(|_| RAError::CommunicationError)?;
    let mut plaintext = Vec::new();

    // println!("write complete");

    match tls.read_to_end(&mut plaintext) {
        Ok(_) => (),
        Err(_) => {
            // println!("get_sigrl_from_intel tls.read_to_end: {:?}", e);
            return Err(RAError::CommunicationError);
        }
    }
    // println!("read_to_end complete");

    parse_response_sigrl(&plaintext)
}

fn get_report_from_intel(ias_key: &str, fd: c_int, quote: Vec<u8>) -> Result<AttnReport, RAError> {
    // println!("get_report_from_intel fd = {:?}", fd);
    let encoded_quote = base64::encode(&quote[..]);
    let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

    let req = format!("POST {}{} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                           API_SUFFIX,
                           REPORT_SUFFIX,
                           IAS_HOSTNAME,
                           ias_key,
                           encoded_json.len(),
                           encoded_json);

    // println!("{}", req);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(IAS_HOSTNAME)
        .map_err(|_| RAError::CommunicationError)?;
    let mut sess = rustls::ClientSession::new(&IAS_CLIENT_CONFIG, dns_name);
    let mut sock = TcpStream::new(fd).map_err(|_| RAError::CommunicationError)?;
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    tls.write(req.as_bytes())
        .map_err(|_| RAError::CommunicationError)?;
    let mut plaintext = Vec::new();

    // println!("write complete");

    tls.read_to_end(&mut plaintext)
        .map_err(|_| RAError::CommunicationError)?;
    // println!("read_to_end complete");
    parse_response_attn_report(&plaintext)
}

#[allow(const_err)]
fn create_attestation_report(
    pub_k: &sgx_ec256_public_t,
    ias_key: &str,
    sign_type: sgx_quote_sign_type_t,
) -> Result<(String, String, String), sgx_status_t> {
    // Workflow:
    // (1) ocall to get the target_info structure (ti) and epid group id (eg)
    // (1.5) get sigrl
    // (2) call sgx_create_report with ti+data, produce an sgx_report_t
    // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

    // (1) get ti + eg
    let mut ti: sgx_target_info_t = sgx_target_info_t::default();
    let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe {
        ocall_sgx_init_quote(
            &mut rt as *mut sgx_status_t,
            &mut ti as *mut sgx_target_info_t,
            &mut eg as *mut sgx_epid_group_id_t,
        )
    };

    // println!("eg = {:?}", eg);

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let eg_num = u32::from_le_bytes(eg);

    // (1.5) get sigrl
    let mut ias_sock: i32 = -1i32;

    let mut sigrl_vec: Vec<u8> = Vec::new();
    let mut sigrl_acquired: bool = false;

    for _ in 0..3 {
        let res = unsafe {
            ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32)
        };

        if res != sgx_status_t::SGX_SUCCESS {
            return Err(res);
        }

        if rt != sgx_status_t::SGX_SUCCESS {
            return Err(rt);
        }

        //println!("Got ias_sock = {}", ias_sock);

        // Now sigrl_vec is the revocation list, a vec<u8>
        match get_sigrl_from_intel(ias_key, ias_sock, eg_num) {
            Ok(v) => {
                sigrl_vec = v;
                sigrl_acquired = true;
                break;
            }
            Err(_) => {
                //println!("get sirl failed, retry...");
            }
        }
    }

    if !sigrl_acquired {
        // println!("Cannot acquire sigrl from Intel for three times");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    // (2) Generate the report
    // Fill ecc256 public key into report_data
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    let mut pub_k_gx = pub_k.gx.clone();
    pub_k_gx.reverse();
    let mut pub_k_gy = pub_k.gy.clone();
    pub_k_gy.reverse();
    report_data.d[..32].clone_from_slice(&pub_k_gx);
    report_data.d[32..].clone_from_slice(&pub_k_gy);

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) => {
            // println!("Report creation => success {:?}", r.body.mr_signer.m);
            Some(r)
        }
        Err(e) => {
            // println!("Report creation => failed {:?}", e);
            return Err(e);
        }
    };

    let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut quote_nonce.rand);
    // println!("rand finished");
    let mut qe_report = sgx_report_t::default();
    const RET_QUOTE_BUF_LEN: u32 = 2048;
    let mut return_quote_buf: [u8; RET_QUOTE_BUF_LEN as usize] = [0; RET_QUOTE_BUF_LEN as usize];
    let mut quote_len: u32 = 0;

    // (3) Generate the quote
    // Args:
    //       1. sigrl: ptr + len
    //       2. report: ptr 432bytes
    //       3. linkable: u32, unlinkable=0, linkable=1
    //       4. spid: sgx_spid_t ptr 16bytes (retrieved inside the app)
    //       5. sgx_quote_nonce_t ptr 16bytes
    //       6. p_sig_rl + sigrl size ( same to sigrl)
    //       7. [out]p_qe_report need further check
    //       8. [out]p_quote
    //       9. quote_size
    let (p_sigrl, sigrl_len) = if sigrl_vec.len() == 0 {
        (ptr::null(), 0)
    } else {
        (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
    };
    let p_report = (&rep.unwrap()) as *const sgx_report_t;
    let quote_type = sign_type;

    let p_nonce = &quote_nonce as *const sgx_quote_nonce_t;
    let p_qe_report = &mut qe_report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let maxlen = RET_QUOTE_BUF_LEN;
    let p_quote_len = &mut quote_len as *mut u32;

    let result = unsafe {
        ocall_get_quote(
            &mut rt as *mut sgx_status_t,
            p_sigrl,
            sigrl_len,
            p_report,
            quote_type,
            p_nonce,
            p_qe_report,
            p_quote,
            maxlen,
            p_quote_len,
        )
    };

    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    if rt != sgx_status_t::SGX_SUCCESS {
        // println!("ocall_get_quote returned {}", rt);
        return Err(rt);
    }

    // Perform a check on qe_report to verify if the qe_report is valid
    match rsgx_verify_report(&qe_report) {
        Ok(()) => {
            // println!("rsgx_verify_report passed!")
        }
        Err(x) => {
            // println!("rsgx_verify_report failed with {:?}", x);
            return Err(x);
        }
    }

    // Check if the qe_report is produced on the same platform
    if ti.mr_enclave.m != qe_report.body.mr_enclave.m
        || ti.attributes.flags != qe_report.body.attributes.flags
        || ti.attributes.xfrm != qe_report.body.attributes.xfrm
    {
        // println!("qe_report does not match current target_info!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    // println!("qe_report check passed");

    // Debug
    // for i in 0..quote_len {
    //     print!("{:02X}", unsafe {*p_quote.offset(i as isize)});
    // }
    // println!("");

    // Check qe_report to defend against replay attack
    // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
    // it received is not modified by the untrusted SW stack, and not a replay.
    // The implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
    // p_qe_report and report.data to confirm the QUOTE has not be modified and
    // is not a replay. It is optional.

    let mut rhs_vec: Vec<u8> = quote_nonce.rand.to_vec();
    rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
    let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).unwrap();
    let lhs_hash = &qe_report.body.report_data.d[..32];

    // println!("rhs hash = {:02X}", rhs_hash.iter().format(""));
    // println!("report hs= {:02X}", lhs_hash.iter().format(""));

    if rhs_hash != lhs_hash {
        // println!("Quote is tampered!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let quote_vec: Vec<u8> = return_quote_buf[..quote_len as usize].to_vec();
    let res =
        unsafe { ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32) };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }
    let attn_report = get_report_from_intel(ias_key, ias_sock, quote_vec)
        .map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;

    Ok((
        attn_report.report,
        attn_report.signature,
        attn_report.certificate,
    ))
}

fn get_ra_cert() -> (CertKeyPair, bool) {
    // Check if the global cert valid
    // If valid, use it directly
    // If invalid, update it before use.
    // Generate Keypair

    // 1. Check if the global cert valid
    //    Need block read here. It should wait for writers to complete
    {
        // Unwrapping failing means the RwLock is poisoned.
        // Simple crash in that case.
        let cache = RACACHE.read().expect("read RA cache");
        if is_tls_config_updated(&cache.gen_time) {
            return (cache.cert_key.clone(), false);
        }
    }

    // 2. Do the update

    // Unwrapping failing means the RwLock is poisoned.
    // Simple crash in that case.
    let mut cache = RACACHE.write().expect("write RA cache");

    // Here is the 100% serialized access to SVRCONFIG
    // No other reader/writer exists in this branch
    // Toc tou check
    if is_tls_config_updated(&cache.gen_time) {
        return (cache.cert_key.clone(), false);
    }

    // Do the renew
    if let Err(e) = renew_ra_cert(&mut cache) {
        // If RA renewal fails, we do not crash for the following reasons.
        // 1. Crashing the enclave causes most data to be lost permanently,
        //    since we do not have persistent key-value storage yet. On the
        //    other hand, RA renewal failure may be temporary. We still have
        //    a chance to recover from this failure in the future.
        // 2. If renewal failed, the old certificate is used, the the client
        //    can decide if they want to keep talking to the enclave.
        // 3. The certificate has a 90 days valid duration. If RA keeps
        //    failing for 90 days, the enclave itself will not serve any
        //    client.
        panic!("RACACHE renewal failed: {:?}", e);
    }

    (cache.cert_key.clone(), true)
}

fn renew_ra_cert(global_ra_cert: &mut RACache) -> Result<(), RAError> {
    let mut ias_key = "00000000000000000000000000000000".to_owned();
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let result = unsafe {
        ocall_get_ias_key(
            &mut rt as *mut sgx_status_t,
            ias_key.as_mut_ptr(),
            ias_key.len() as u32,
        )
    };
    if result != sgx_status_t::SGX_SUCCESS
        || rt != sgx_status_t::SGX_SUCCESS
        || !ias_key.chars().all(|x| x.is_alphanumeric())
    {
        return Err(RAError::APIKeyError);
    }

    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    ecc_handle.open().map_err(|_| RAError::CertGeneration)?;
    let (mut prv_k, pub_k) = ecc_handle
        .create_key_pair()
        .map_err(|_| RAError::CertGeneration)?;

    let (attn_report, sig, cert) = match create_attestation_report(
        &pub_k,
        &ias_key,
        sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
    ) {
        Ok(r) => r,
        Err(_e) => {
            #[cfg(not(feature = "production"))]
            println!("Error in create_attestation_report: {:?}", _e);
            return Err(RAError::CertGeneration);
        }
    };

    let payload = attn_report + "|" + &sig + "|" + &cert;
    let cert_key = match crate::cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle) {
        Ok(r) => r,
        Err(_e) => {
            #[cfg(not(feature = "production"))]
            println!("Error in gen_ecc_cert: {:?}", _e);
            return Err(RAError::CertGeneration);
        }
    };
    ecc_handle.close().map_err(|_| RAError::CertGeneration)?;
    prv_k.r.zeroize();
    global_ra_cert.cert_key = cert_key;
    global_ra_cert.gen_time = SystemTime::now();

    Ok(())
}

/// Returns the TLS session configuration
/// fast path: it's in the cache (`SVRCONFIGCACHE` lazy static), so can be returned directly
/// slow path: needs to generate a key pair, remotely attest the public key and generate the TLS certificate and configuration
pub(crate) fn get_tls_config() -> Arc<rustls::ServerConfig> {
    // To re-use existing TLS cache, we need to first check if the server has
    // updated his RA cert
    let (cert_key, invalidate_cache) = get_ra_cert();
    let mut s = DefaultHasher::new();
    cert_key.cert.hash(&mut s);
    let stat_hash = s.finish();
    // invalidate_cache is true iff. ra is renewed in the above func call
    // if ra cert is pulled from cache, then we can try to do it quickly.
    if !invalidate_cache {
        if let Ok(cfg_cache) = SVRCONFIGCACHE.try_read() {
            if let Some(cfg) = cfg_cache.get(&stat_hash) {
                // Everything matched. Be quick!
                return cfg.clone();
            }
        }
    } else {
        // ra cert is updated. so we need to invalidate the cache
        // THIS IS BLOCKING!
        match SVRCONFIGCACHE.write() {
            Ok(mut cfg_cache) => {
                //println!("SVRCONFIGCACHE invalidate all config cache!");
                cfg_cache.clear();
            }
            Err(_) => {
                // Poisoned
                // println!("SVRCONFIGCACHE invalidate cache failed {}!", x);
            }
        }
    }

    // FIXME: client auth?
    let authenticator = rustls::NoClientAuth::new();
    let mut cfg = rustls::ServerConfig::new(authenticator);
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_key.cert));
    let privkey = rustls::PrivateKey(cert_key.private_key.expose());

    cfg.set_single_cert(certs, privkey).expect("TLS config");

    let final_arc = Arc::new(cfg); // Create an Arc

    if let Ok(mut cfg_cache) = SVRCONFIGCACHE.try_write() {
        let _ = cfg_cache.insert(stat_hash, final_arc.clone()); // Overwrite
    }
    final_arc
}
