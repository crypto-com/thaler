#![feature(proc_macro_hygiene)]

use enclave_macro::{get_mrsigner, get_network_id, get_tqe_mrenclave};
use ra_client::{EnclaveCertVerifier, EnclaveCertVerifierConfig, EnclaveInfo};
use rustls::{Certificate, ClientSession, Session};
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

pub fn get_cert(port: u32) -> Certificate {
    let address = format!("127.0.0.1:{}", port);
    println!("connect to address: {}", address);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str("localhost")
        .unwrap()
        .to_owned();
    let verifier = EnclaveCertVerifier::new(EnclaveCertVerifierConfig::new_with_enclave_info(
        EnclaveInfo {
            mr_signer: get_mrsigner!(),
            mr_enclave: Some(get_tqe_mrenclave!()),
            previous_mr_enclave: None,
            cpu_svn: [0; 16],
            isv_svn: 0,
            isv_prod_id: get_network_id!(),
            attributes: [0; 16],
        },
    ))
    .expect("EnclaveCertVerifier::new");
    let client_config = Arc::new(
        verifier
            .into_client_config(true)
            .expect("into_client_config"),
    );
    // client_config.dangerous().set_certificate_verifier();
    let mut session = ClientSession::new(&client_config, dns_name.as_ref());
    let mut conn = TcpStream::connect(&address)
        .map_err(|e| {
            println!("can not connect to address: {}, {:?}", address, e);
        })
        .unwrap();
    let mut tls = rustls::Stream::new(&mut session, &mut conn);
    tls.write_all(&[0; 32]).expect("write to tls");
    tls.flush().expect("flush");
    let mut r = [0u8; 16];
    tls.read(&mut r).expect("read");
    println!("get result: {:?}", &r);
    let certifications = session
        .get_peer_certificates()
        .expect("get certifications first time");
    println!("first get certification finished");
    assert_eq!(certifications.len(), 1);
    certifications[0].clone()
}

pub fn test_cert_refresh(port: u32, sleep_secs: u64) {
    let cert_1 = get_cert(port);
    sleep(Duration::from_secs(sleep_secs));
    let cert_2 = get_cert(port);
    assert_ne!(cert_1, cert_2);
}
fn main() {
    let args: Vec<_> = env::args().collect();
    test_cert_refresh(args[1].parse().unwrap(), args[2].parse().unwrap());
}
