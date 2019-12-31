pub use rustls;
use std::env;
use std::fs;
use std::io::BufReader;
use std::sync::Arc;

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let rsa_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
            .expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

pub fn get_tls_config() -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    let certs = load_certs(&env::var("MOCK_TLS_CERTS").expect("MOCK_TLS_CERTS missing"));
    let privkey = load_private_key(&env::var("MOCK_TLS_KEY").expect("MOCK_TLS_KEY missing"));
    config
        .set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .expect("bad certificates/private key");
    Arc::new(config)
}
