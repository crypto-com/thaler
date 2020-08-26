use chrono::Duration;
use ra_client::EnclaveCertVerifier;
use ra_enclave::{EnclaveRaConfig, EnclaveRaContext, DEFAULT_EXPIRATION_SECS};
use rustls::{ClientSession, ServerSession, StreamOwned};
use std::net::TcpStream;
use std::sync::Arc;
use webpki::DNSNameRef;

/// create TLS stream connecting to remote address
/// (uses the client-side certificate from EnclaveRaContext
/// and includes EnclaveCertVerifier for verifying the attestation payload)
pub fn create_tls_client_stream(
    context: &EnclaveRaContext,
    verifier: EnclaveCertVerifier,
    dns_name: &str,
    address: &str,
) -> std::io::Result<StreamOwned<ClientSession, TcpStream>> {
    log::info!("Creating enclave-to-enclave attested TLS client stream");
    let certificate = context
        .get_certificate()
        .expect("Unable to generate remote attestation certificate");

    let mut client_config = verifier
        .into_client_config()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    certificate
        .configure_client_config(&mut client_config)
        .expect("Unable to configure TLS client config with certificate");
    let client_config = Arc::new(client_config);

    let dns_name_ref = DNSNameRef::try_from_ascii_str(dns_name).expect("Invalid DNS name");

    let client_session = ClientSession::new(&client_config, dns_name_ref);
    let tcp_stream = match TcpStream::connect(address) {
        Ok(tcp_stream) => tcp_stream,
        Err(err) => {
            log::error!("Error while connecting to TCP stream");
            return Err(err);
        }
    };

    log::info!("Created enclave-to-enclave TLS client stream");

    Ok(StreamOwned::new(client_session, tcp_stream))
}

/// create TLS stream listening to other connections
/// (uses the client-side certificate from EnclaveRaContext
/// and includes EnclaveCertVerifier for verifying the attestation payload)
pub fn create_tls_server_stream(
    context: &EnclaveRaContext,
    verifier: EnclaveCertVerifier,
    stream: TcpStream,
    verify_client_mrenclave: bool,
) -> std::io::Result<StreamOwned<ServerSession, TcpStream>> {
    log::info!("Creating enclave-to-enclave attested TLS server stream");
    let certificate = context
        .get_certificate()
        .expect("Unable to create remote attestation certificate");
    let mut tls_server_config = verifier
        .into_client_verifying_server_config(verify_client_mrenclave)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    certificate
        .configure_server_config(&mut tls_server_config)
        .expect("Unable to create TLS server config");

    let tls_server_config = Arc::new(tls_server_config);

    let tls_session = ServerSession::new(&tls_server_config);

    log::info!("Created enclave-to-enclave attested TLS server stream");

    Ok(StreamOwned::new(tls_session, stream))
}

/// TODO: aesm used directly inside an enclave
pub fn create_ra_context() -> Arc<EnclaveRaContext> {
    log::info!("Creating enclave remote attestation context");

    let certificate_expiration_time = {
        option_env!("CERTIFICATE_EXPIRATION_SECS").map(|s| {
            let sec = s
                .parse()
                .expect("invalid CERTIFICATE_EXPIRATION_SECS, expect u64");
            Duration::seconds(sec)
        })
    };
    let config = EnclaveRaConfig {
        sp_addr: "ra-sp-server".to_string(),
        certificate_validity_secs: DEFAULT_EXPIRATION_SECS as u32,
        certificate_expiration_time,
    };

    let enclave_ra_context =
        EnclaveRaContext::new(&config).expect("Unable to create new remote attestation context");

    log::info!("Created enclave remote attestation context");

    Arc::new(enclave_ra_context)
}
