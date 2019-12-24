pub use rustls;
use std::sync::Arc;

pub fn get_tls_config() -> Arc<rustls::ServerConfig> {
    Arc::new(rustls::ServerConfig::new(rustls::NoClientAuth::new()))
}
