pub use rustls;
use std::sync::Arc;

const MOCK_CERT_FILE: &[u8] = include_bytes!("../certs/selfsigned.crt");
const MOCK_KEY_FILE: &[u8] = include_bytes!("../certs/private.key");

fn load_certs() -> Vec<rustls::Certificate> {
    rustls::internal::pemfile::certs(&mut std::io::Cursor::new(MOCK_CERT_FILE.to_vec())).unwrap()
}

fn load_private_key() -> rustls::PrivateKey {
    rustls::internal::pemfile::rsa_private_keys(&mut std::io::Cursor::new(MOCK_KEY_FILE.to_vec()))
        .expect("file contains invalid rsa private key")[0]
        .clone()
}

pub fn get_tls_config() -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    let certs = load_certs();
    let privkey = load_private_key();
    config
        .set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .expect("bad certificates/private key");
    Arc::new(config)
}
