use super::sgx::EnclaveAttr;
use crate::TransactionObfuscation;
use chain_core::tx::data::TxId;
use chain_core::tx::{TxAux, TxWithOutputs};
use client_common::SECP;
use client_common::{
    Error, ErrorKind, PrivateKey, Result, ResultExt, SignedTransaction, Transaction,
};
use enclave_protocol::{
    DecryptionRequest, DecryptionResponse, EncryptionRequest, EncryptionResponse,
    TxQueryInitRequest, TxQueryInitResponse,
};
use parity_scale_codec::{Decode, Encode};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

fn get_tls_config() -> Arc<rustls::ClientConfig> {
    // TODO: static config cache
    let mut client_cfg = rustls::ClientConfig::new();
    // TODO: client auth?

    // this is needed for the custom extra validation of the attestation report in the certificate extension
    client_cfg
        .dangerous()
        .set_certificate_verifier(Arc::new(EnclaveAttr {}));
    client_cfg.versions.clear();
    // TODO: test/try 1.3 and possibly switch
    client_cfg.versions.push(rustls::ProtocolVersion::TLSv1_2);
    Arc::new(client_cfg)
}

/// Implementation of transaction obfuscation which directly talks to transaction decryption query and encryption enclaves
/// TODO: querying from multiple nodes / addresses
#[derive(Debug, Clone)]
pub struct DefaultTransactionObfuscation {
    tqe_address: String,
    tqe_hostname: String,
}

impl DefaultTransactionObfuscation {
    /// tqe_address: connection string <HOST/IP:PORT>
    /// tqe_hostname: expected hostname (e.g. localhost in testing)
    pub fn new(tqe_address: String, tqe_hostname: String) -> Self {
        DefaultTransactionObfuscation {
            tqe_address,
            tqe_hostname,
        }
    }
}

impl TransactionObfuscation for DefaultTransactionObfuscation {
    fn decrypt(
        &self,
        transaction_ids: &[TxId],
        private_key: &PrivateKey,
    ) -> Result<Vec<Transaction>> {
        let client_config = get_tls_config();
        let dns_name = webpki::DNSNameRef::try_from_ascii_str(&self.tqe_hostname).chain(|| {
            (
                ErrorKind::InvalidInput,
                format!("Invalid TQE hostname: {}", self.tqe_hostname),
            )
        })?;
        let mut sess = rustls::ClientSession::new(&client_config, dns_name);

        let mut conn = TcpStream::connect(&self.tqe_address).chain(|| {
            (
                ErrorKind::ConnectionError,
                format!("Unable to connect to TQE address: {}", self.tqe_address),
            )
        })?;

        let mut tls = rustls::Stream::new(&mut sess, &mut conn);
        tls.write_all(&TxQueryInitRequest::DecryptChallenge.encode())
            .chain(|| {
                (
                    ErrorKind::IoError,
                    "Unable to write to TQE connection stream",
                )
            })?;
        let mut challenge = [0u8; 33];
        tls.read_exact(&mut challenge).chain(|| {
            (
                ErrorKind::IoError,
                "Unable to read from TQE connection stream",
            )
        })?;
        let resp = TxQueryInitResponse::decode(&mut challenge.as_ref());
        let ch = match resp {
            Ok(TxQueryInitResponse::DecryptChallenge(challenge)) => challenge,
            _ => {
                return Err(Error::new(
                    ErrorKind::IoError,
                    "unexpected response from TQE connection stream",
                ))
            }
        };
        let request = SECP.with(|secp| {
            DecryptionRequest::create(&secp, transaction_ids.to_owned(), ch, &private_key.into())
        });
        tls.write_all(&request.encode()).chain(|| {
            (
                ErrorKind::IoError,
                "Unable to write to TQE connection stream",
            )
        })?;

        let mut plaintext = Vec::new();
        match tls.read_to_end(&mut plaintext) {
            Ok(_) => {
                let txs = DecryptionResponse::decode(&mut plaintext.as_slice())
                    .chain(|| {
                        (
                            ErrorKind::DeserializationError,
                            "Unable to deserialize decryption response from enclave",
                        )
                    })?
                    .txs;

                let transactions = txs
                    .into_iter()
                    .map(|tx| match tx {
                        TxWithOutputs::Transfer(t) => Transaction::TransferTransaction(t),
                        TxWithOutputs::StakeWithdraw(t) => {
                            Transaction::WithdrawUnbondedStakeTransaction(t)
                        }
                    })
                    .collect::<Vec<Transaction>>();

                Ok(transactions)
            }
            Err(_) => Err(Error::new(
                ErrorKind::IoError,
                "Unable to read from TQE connection stream",
            )),
        }
    }

    fn encrypt(&self, transaction: SignedTransaction) -> Result<TxAux> {
        let client_config = get_tls_config();
        let dns_name = webpki::DNSNameRef::try_from_ascii_str(&self.tqe_hostname).chain(|| {
            (
                ErrorKind::InvalidInput,
                format!("Invalid TQE hostname: {}", self.tqe_hostname),
            )
        })?;
        let mut sess = rustls::ClientSession::new(&client_config, dns_name);

        let mut conn = TcpStream::connect(&self.tqe_address).chain(|| {
            (
                ErrorKind::ConnectionError,
                format!("Unable to connect to TQE address: {}", self.tqe_address),
            )
        })?;
        let mut tls = rustls::Stream::new(&mut sess, &mut conn);
        let request = match transaction {
            SignedTransaction::TransferTransaction(tx, witness) => {
                TxQueryInitRequest::Encrypt(Box::new(EncryptionRequest::TransferTx(tx, witness)))
            }
            SignedTransaction::DepositStakeTransaction(tx, witness) => {
                TxQueryInitRequest::Encrypt(Box::new(EncryptionRequest::DepositStake(tx, witness)))
            }
            SignedTransaction::UnbondStakeTransaction(tx, witness) => {
                return Ok(TxAux::UnbondStakeTx(tx, witness));
            }
            SignedTransaction::WithdrawUnbondedStakeTransaction(tx, state, witness) => {
                TxQueryInitRequest::Encrypt(Box::new(EncryptionRequest::WithdrawStake(
                    tx, state, witness,
                )))
            }
        };
        tls.write_all(&request.encode()).chain(|| {
            (
                ErrorKind::IoError,
                "Unable to write to TQE connection stream",
            )
        })?;
        let mut plaintext = Vec::new();
        match tls.read_to_end(&mut plaintext) {
            Ok(_) => {
                let tx = EncryptionResponse::decode(&mut plaintext.as_slice())
                    .chain(|| {
                        (
                            ErrorKind::DeserializationError,
                            "Unable to deserialize decryption response from enclave",
                        )
                    })?
                    .tx;
                Ok(TxAux::EnclaveTx(tx))
            }
            Err(_) => Err(Error::new(
                ErrorKind::IoError,
                "Unable to read from TQE connection stream",
            )),
        }
    }
}
