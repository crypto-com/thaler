#[cfg(target_env = "sgx")]
mod sgx_module;
#[cfg(target_env = "sgx")]
use chrono::Duration;

#[cfg(target_env = "sgx")]
fn main() -> std::io::Result<()> {
    let cert_expiration: Option<Duration> = option_env!("CERTIFICATE_EXPIRATION_SECS").map(|s| {
        let sec = s
            .parse()
            .expect("invalid CERTIFICATE_EXPIRATION_SECS, expect u64");
        Duration::seconds(sec)
    });
    sgx_module::entry(cert_expiration)
}

#[cfg(not(target_env = "sgx"))]
fn main() {
    println!("`tx-query-next` cannot be compiled for non-sgx environment!");
}
