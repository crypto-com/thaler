use crate::hd_wallet::KeyChain;
use crate::hd_wallet::{ChainPath, DefaultKeyChain, ExtendedPrivKey};
use crate::service::hw_key_service::HardwareWalletAction;
use crate::service::{HDAccountType, HdKey};
use crate::{HDSeed, Mnemonic};
use client_common::{
    Error, ErrorKind, PrivateKey, PrivateKeyAction, PublicKey, Result, ResultExt, Transaction,
};
use parity_scale_codec::alloc::collections::BTreeMap;
use protocol::{get_data_from_stream, send_data_to_stream, Decode, Encode, Request, Response};
use secp256k1::recovery::RecoverableSignature;
use secp256k1::schnorrsig::SchnorrSignature;
use std::env;
use std::net::TcpStream;
use std::net::{SocketAddr, TcpListener};

/// mock hardware key
pub struct MockHardwareKey {
    server_addr: SocketAddr,
    hd_path: String,
}

impl MockHardwareKey {
    fn send(&self, request: Request) -> Result<Response> {
        let mut stream = TcpStream::connect(self.server_addr).unwrap();
        let raw_data = request.encode()?;
        send_data_to_stream(&mut stream, &raw_data)?;
        let response_raw = get_data_from_stream(&mut stream)?;
        let response = Response::decode(response_raw)
            .map_err(|_| Error::new(ErrorKind::DeserializationError, "get invalid response"))?;
        Ok(response)
    }
}

impl PrivateKeyAction for MockHardwareKey {
    fn sign(&self, tx: &Transaction) -> Result<RecoverableSignature> {
        let request = Request::SignTx((tx.clone(), self.hd_path.clone()));
        let response = self.send(request)?;
        match response {
            Response::SignTx(signature) => Ok(signature),
            _ => unreachable!(),
        }
    }

    fn schnorr_sign(&self, tx: &Transaction) -> Result<SchnorrSignature> {
        let request = Request::SchnorrSignTx((tx.clone(), self.hd_path.clone()));
        let response = self.send(request)?;
        match response {
            Response::SchnorrSignTx(raw_data) => {
                let signature = SchnorrSignature::from_default(&raw_data).map_err(|_| {
                    Error::new(ErrorKind::DeserializationError, "deserde signature failed")
                })?;
                Ok(signature)
            }
            _ => unreachable!(),
        }
    }

    fn public_key(&self) -> Result<PublicKey> {
        let request = Request::GetPublicKey(self.hd_path.clone());
        let response = self.send(request)?;
        match response {
            Response::PublicKey(public_key) => Ok(public_key),
            _ => unreachable!(),
        }
    }
}

/// mock hardware key service
#[derive(Debug, Clone)]
pub struct MockHardwareWallet {
    address: SocketAddr,
    hd_key: HdKey,
    hdpath_pubkey_pair: BTreeMap<String, PublicKey>,
}

impl Default for MockHardwareWallet {
    fn default() -> Self {
        let server_port = match env::var("MOCK_HARDWARD_PORT") {
            Ok(value) => value,
            Err(_) => "8765".to_string(),
        };
        let socket_address = format!("127.0.0.1:{}", server_port)
            .parse()
            .expect("invalid mock hardware wallet tcp server address");
        //let mnemonic = Mnemonic::new();
        let w = "ordinary mandate edit father snack mesh history identify print borrow skate unhappy cattle tiny first".into();
        let mnemonic = Mnemonic::from_secstr(&w).unwrap();
        let hd_seed = HDSeed::from(&mnemonic);
        let hd_key = HdKey {
            staking_index: 0,
            transfer_index: 0,
            viewkey_index: 0,
            seed: hd_seed,
        };
        Self {
            hd_key,
            address: socket_address,
            hdpath_pubkey_pair: BTreeMap::default(),
        }
    }
}

impl MockHardwareWallet {
    /// create a MockHardwarewallet
    pub fn new() -> Self {
        Self::default()
    }

    fn create_hd_path(account_type: HDAccountType, index: u32) -> String {
        format!("m/44'/1'/{}'/0/{}", account_type.index(), index)
    }

    fn get_private_key(&self, hd_path: &str) -> Result<PrivateKey> {
        let chain_path = ChainPath::from(hd_path);
        let key_chain = DefaultKeyChain::new(
            ExtendedPrivKey::with_seed(&self.hd_key.seed.bytes)
                .chain(|| (ErrorKind::InternalError, "Invalid seed bytes"))?,
        );

        let (extended_private_key, _) = key_chain.derive_private_key(chain_path).chain(|| {
            (
                ErrorKind::InternalError,
                "Failed to derive HD wallet private key",
            )
        })?;

        let private_key = PrivateKey::from(extended_private_key.private_key);
        Ok(private_key)
    }

    fn get_public_key(&self, hd_path: &str) -> Result<PublicKey> {
        log::info!("request to get a public key");
        match self.hdpath_pubkey_pair.get(hd_path) {
            None => Err(Error::new(
                ErrorKind::InvalidInput,
                "can not find public key",
            )),
            Some(pub_key) => Ok(pub_key.clone()),
        }
    }

    fn get_hd_path(&self, public_key: &PublicKey) -> Result<String> {
        log::info!("request to get the hd path");
        for (hd_path, pub_key) in self.hdpath_pubkey_pair.iter() {
            log::debug!("public_key: {:?}", pub_key);
            if public_key == pub_key {
                return Ok(hd_path.clone());
            }
        }
        Err(Error::new(ErrorKind::InvalidInput, "can not find hd_path"))
    }

    fn create_transfer_address(&mut self) -> Result<Response> {
        log::info!("request for a new transfer address");
        let account_type = HDAccountType::Transfer;
        self.hd_key.transfer_index += 1;
        let hd_path = Self::create_hd_path(account_type, self.hd_key.transfer_index);
        let private_key = self.get_private_key(&hd_path)?;
        let public_key = PublicKey::from(&private_key);
        self.hdpath_pubkey_pair.insert(hd_path, public_key.clone());
        log::info!("public_key: {:?}", public_key);
        Ok(Response::NewTransferAddr(public_key))
    }

    fn create_staking_address(&mut self) -> Result<Response> {
        log::info!("request for a new staking address");
        let account_type = HDAccountType::Staking;
        self.hd_key.staking_index += 1;
        let hd_path = Self::create_hd_path(account_type, self.hd_key.staking_index);
        let private_key = self.get_private_key(&hd_path)?;
        let public_key = PublicKey::from(&private_key);
        self.hdpath_pubkey_pair.insert(hd_path, public_key.clone());
        Ok(Response::NewStakingAddr(public_key))
    }

    fn sign_tx(&self, tx: &Transaction, hd_path: &str) -> Result<Response> {
        log::info!("request to sign transaction");
        let private_key = self.get_private_key(hd_path)?;
        let signature = private_key.sign(tx)?;
        Ok(Response::SignTx(signature))
    }

    fn schnorr_sign_tx(&self, tx: &Transaction, hd_path: &str) -> Result<Response> {
        log::info!("request to schnorr sign transaction");
        let private_key = self.get_private_key(hd_path)?;
        let signature = private_key.schnorr_sign(tx)?;
        let raw_data = signature.serialize_default().to_vec();
        Ok(Response::SchnorrSignTx(raw_data))
    }

    fn handle_request(&mut self, raw_data: Vec<u8>) -> Result<Response> {
        let request = Request::decode(raw_data)
            .map_err(|_| Error::new(ErrorKind::DeserializationError, "invalid request"))?;
        let response = match request {
            Request::GetPublicKey(hd_path) => {
                let public_key = self.get_public_key(&hd_path)?;
                Response::PublicKey(public_key)
            }
            Request::NewTransferAddr => self.create_transfer_address()?,
            Request::NewStakingAddr => self.create_staking_address()?,
            Request::SignTx((tx, hd_path_str)) => self.sign_tx(&tx, &hd_path_str)?,
            Request::SchnorrSignTx((tx, hd_path_str)) => self.schnorr_sign_tx(&tx, &hd_path_str)?,
            Request::GetHdPath(pub_key) => {
                let hd_path = self.get_hd_path(&pub_key)?;
                log::info!("get hd path: {}", hd_path);
                Response::HdPath(hd_path)
            }
        };
        Ok(response)
    }

    fn serve(&mut self, mut stream: TcpStream) -> Result<()> {
        let request_raw_data = protocol::get_data_from_stream(&mut stream)?;
        let response = self.handle_request(request_raw_data)?;
        log::info!("send response to client: {:?}", response);
        let response_raw_data = response.encode()?;
        log::info!(
            "response raw data: {:?}, {}",
            response_raw_data,
            response_raw_data.len()
        );
        let _ = send_data_to_stream(&mut stream, &response_raw_data)?;
        Ok(())
    }

    /// run the hardware wallet server
    pub fn run(&mut self) {
        let listener = TcpListener::bind(self.address).unwrap();
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    log::info!("comming a request");
                    self.serve(stream).unwrap();
                }
                Err(e) => {
                    log::error!("error tcp stream: {:?}", e);
                }
            }
        }
    }
}

/// Mock hardare service
#[derive(Clone, Debug)]
pub struct MockHardwareService {
    server_address: SocketAddr,
}

impl Default for MockHardwareService {
    fn default() -> Self {
        let server_port = match env::var("MOCK_HARDWARD_PORT") {
            Ok(value) => value,
            Err(_) => "8765".to_string(),
        };
        let server_address = format!("127.0.0.1:{}", server_port)
            .parse()
            .expect("invalid mock hardware wallet tcp server address");
        Self { server_address }
    }
}

impl MockHardwareService {
    /// create a MockHardwareService
    pub fn new() -> Self {
        Self::default()
    }

    fn send(&self, request: &Request) -> Result<Response> {
        let mut stream = TcpStream::connect(self.server_address).unwrap();
        send_data_to_stream(&mut stream, &request.encode()?)?;
        let response_raw = get_data_from_stream(&mut stream)?;
        let response = Response::decode(response_raw)
            .map_err(|_e| Error::new(ErrorKind::DeserializationError, "invalid response"))?;
        Ok(response)
    }
}

impl HardwareWalletAction for MockHardwareService {
    fn new_transfer_address(&self) -> Result<PublicKey> {
        let request = Request::NewTransferAddr;
        let response = self.send(&request)?;
        match response {
            Response::NewTransferAddr(pub_key) => Ok(pub_key),
            _ => unreachable!(),
        }
    }

    fn new_staking_address(&self) -> Result<PublicKey> {
        let request = Request::NewStakingAddr;
        let response = self.send(&request)?;
        match response {
            Response::NewStakingAddr(pub_key) => Ok(pub_key),
            other => {
                log::error!("get unexpected response: {:?}", other);
                unreachable!()
            }
        }
    }

    fn get_sign_key(&self, public_key: &PublicKey) -> Result<Box<dyn PrivateKeyAction>> {
        let request = Request::GetHdPath(public_key.clone());
        let response = self.send(&request)?;
        let hd_path = match response {
            Response::HdPath(hd_path) => hd_path,
            _ => unreachable!(),
        };
        let hw_key = MockHardwareKey {
            server_addr: self.server_address,
            hd_path,
        };
        Ok(Box::new(hw_key))
    }
}

mod protocol {
    use super::RecoverableSignature;
    use client_common::{Error, ErrorKind, PublicKey, Result, Transaction};
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Serialize};
    use std::io::{Read, Write};

    #[derive(Debug, Serialize, Deserialize)]
    pub enum Request {
        NewStakingAddr,
        NewTransferAddr,
        SignTx((Transaction, String)),
        SchnorrSignTx((Transaction, String)),
        GetPublicKey(String),
        GetHdPath(PublicKey),
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub enum Response {
        NewStakingAddr(PublicKey),
        NewTransferAddr(PublicKey),
        PublicKey(PublicKey),
        HdPath(String),
        ViewKey(PublicKey),
        SignTx(RecoverableSignature),
        SchnorrSignTx(Vec<u8>),
    }

    pub fn get_data_from_stream<T: Read>(stream: &mut T) -> Result<Vec<u8>> {
        let mut len_info = [0_u8; 8];
        let _ = stream
            .read(&mut len_info)
            .map_err(|_| Error::new(ErrorKind::IoError, "read from tcp stream failed"))?;
        let data_len = usize::from_le_bytes(len_info);
        let mut data = vec![0_u8; data_len];
        let _ = stream
            .read(&mut data)
            .map_err(|_| Error::new(ErrorKind::IoError, "read from tcp stream failed"))?;
        Ok(data)
    }

    pub fn send_data_to_stream<W: Write>(stream: &mut W, data: &[u8]) -> Result<usize> {
        let data_len: [u8; 8] = data.len().to_le_bytes();
        let l1 = stream
            .write(&data_len)
            .map_err(|_| Error::new(ErrorKind::IoError, "write to tcp stream failed"))?;
        let l2 = stream
            .write(&data[..])
            .map_err(|_| Error::new(ErrorKind::IoError, "write to tcp stream failed"))?;
        Ok(l1 + l2)
    }

    pub trait Encode: Serialize {
        fn encode(&self) -> Result<Vec<u8>> {
            let data_str = serde_json::to_string(self)
                .map_err(|_| Error::new(ErrorKind::SerializationError, "serialize error"))?;
            Ok(data_str.into_bytes())
        }
    }

    pub trait Decode: DeserializeOwned {
        fn decode(encoded: Vec<u8>) -> Result<Self> {
            let data_str = String::from_utf8(encoded).unwrap();
            let result = serde_json::from_str(&data_str)
                .map_err(|_| Error::new(ErrorKind::DeserializationError, "deserialize  error"))?;
            Ok(result)
        }
    }
    impl Encode for Request {}
    impl Encode for Response {}
    impl Decode for Request {}
    impl Decode for Response {}
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_decode() {
        let raw_data = vec![
            123, 34, 83, 99, 104, 110, 111, 114, 114, 83, 105, 103, 110, 84, 120, 34, 58, 91, 57,
            50, 44, 51, 48, 44, 50, 51, 51, 44, 55, 48, 44, 50, 48, 55, 44, 50, 52, 56, 44, 54, 49,
            44, 50, 50, 56, 44, 50, 52, 54, 44, 49, 53, 48, 44, 49, 55, 50, 44, 49, 49, 48, 44, 49,
            54, 54, 44, 49, 53, 57, 44, 49, 49, 52, 44, 50, 51, 52, 44, 55, 49, 44, 55, 51, 44, 49,
            49, 48, 44, 50, 49, 44, 50, 52, 49, 44, 49, 48, 49, 44, 49, 48, 56, 44, 49, 48, 56, 44,
            50, 44, 53, 49, 44, 49, 55, 54, 44, 50, 50, 53, 44, 54, 48, 44, 49, 48, 44, 50, 51, 50,
            44, 49, 53, 44, 52, 52, 44, 50, 50, 56, 44, 49, 52, 53, 44, 50, 50, 48, 44, 49, 55, 52,
            44, 49, 50, 56, 44, 51, 52, 44, 49, 57, 50, 44, 50, 52, 55, 44, 49, 50, 48, 44, 50, 50,
            49, 44, 49, 54, 57, 44, 50, 51, 49, 44, 51, 52, 44, 49, 55, 51, 44, 49, 55, 53, 44, 56,
            52, 44, 49, 56, 49, 44, 49, 48, 48, 44, 50, 49, 49, 44, 49, 49, 55, 44, 49, 56, 56, 44,
            49, 49, 44, 55, 48, 44, 49, 51, 55, 44, 50, 48, 44, 49, 53, 56, 44, 49, 48, 55, 44, 49,
            53, 57, 44, 50, 49, 56, 44, 50, 51, 51, 44, 49, 57, 57, 93, 125,
        ];
        let response = Response::decode(raw_data);
        println!("{:?}", response);
        assert!(response.is_ok())
    }
}
