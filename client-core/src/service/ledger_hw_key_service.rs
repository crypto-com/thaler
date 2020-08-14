use crate::hd_wallet::ChainPath;
use crate::service::hw_key_service::HardwareWalletAction;
use client_common::{
    Error, ErrorKind, PrivateKeyAction, PublicKey, Result, ResultExt, Transaction,
};
use ledger_crypto::{APDUTransport, Address, CryptoApp};
use parity_scale_codec::Encode;
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use secp256k1::schnorrsig::SchnorrSignature;
use std::sync::Arc;
use tokio::runtime::Runtime;
use zx_bip44::BIP44Path;

/// Hedger Service
#[derive(Clone)]
pub struct LedgerService {
    /// crypto app of ledger
    pub app: Arc<CryptoApp>,
    /// confirmation on ledger or not
    pub require_confirmation: bool,
}

impl std::fmt::Debug for LedgerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerService")
            .field("app", &"CryptoApp")
            .field("require_confirmation", &self.require_confirmation)
            .finish()
    }
}

macro_rules! sync {
    ($f:expr, $e: expr) => {{
        let mut run_time = Runtime::new().unwrap();
        run_time.block_on($f).chain(|| (ErrorKind::LedgerError, $e))
    }};
}

impl LedgerService {
    /// create a new LedgerService
    pub fn new(require_confirmation: bool) -> Result<Self> {
        let wrapper = ledger::TransportNativeHID::new()
            .chain(|| (ErrorKind::LedgerError, "can't find ledger device, see more: https://support.ledger.com/hc/en-us/articles/115005165269-Fix-connection-issues"))?;
        let transport = APDUTransport {
            transport_wrapper: wrapper,
        };
        let app = CryptoApp::new(transport);
        let app_info = sync!(app.get_app_info(), "get app info failed")?;
        if app_info.app_name.to_lowercase() != "cryp" {
            return Err(Error::new(ErrorKind::LedgerError, "not CRO app"));
        }
        Ok(Self {
            app: Arc::new(app),
            require_confirmation,
        })
    }
}

impl HardwareWalletAction for LedgerService {
    fn get_public_key(&self, chain_path: ChainPath) -> Result<PublicKey> {
        let path = BIP44Path::from_string(chain_path.to_string())
            .chain(|| (ErrorKind::InvalidInput, "input invalid hd path"))?;
        let f = self.app.get_address(&path, self.require_confirmation);
        let resp: Address = sync!(f, "get public key failed")?;
        PublicKey::deserialize_from(&resp.public_key)
    }

    fn get_sign_key(&self, hd_path: &ChainPath) -> Result<Box<dyn PrivateKeyAction>> {
        let path = BIP44Path::from_string(hd_path.to_string())
            .chain(|| (ErrorKind::InvalidInput, "invalid hd path"))?;
        let hw_key = LedgerSignKey {
            path,
            service: self.clone(),
        };
        Ok(Box::new(hw_key))
    }
}

/// represent a private key, can sign msg in the ledger device with `path` using `service`
pub struct LedgerSignKey {
    path: BIP44Path,
    service: LedgerService,
}

/// the header defined in `app/src/coin.h` of ledger crypto app, the size is `CRO_HEADER_SIZE` which is `2`
/// the first one is `CRO_TX_AUX_ENUM_ENCLAVE_TX` or `CRO_TX_AUX_ENUM_PUBLIC_TX`
/// the seconde one depends on the tx type, which is defined in `app/src/parser_txdef.h` of ledger crypto app
const CRO_TX_AUX_ENUM_ENCLAVE_TX: u8 = 0;
const CRO_TX_AUX_ENUM_PUBLIC_TX: u8 = 1;

const CRO_TX_AUX_PUBLIC_AUX_UNBOND_STAKE: u8 = 0;
const CRO_TX_AUX_PUBLIC_AUX_UNJAIL: u8 = 1;
const CRO_TX_AUX_PUBLIC_AUX_NODE_JOIN: u8 = 2;

const CRO_TX_AUX_ENCLAVE_TRANSFER_TX: u8 = 0;
const CRO_TX_AUX_ENCLAVE_DEPOSIT_STAKE: u8 = 1;
const CRO_TX_AUX_ENCLAVE_WITHDRAW_UNBOUNDED_STAKE: u8 = 2;

fn get_blob(tx: &Transaction) -> Vec<u8> {
    match tx {
        Transaction::UnbondStakeTransaction(tx) => {
            let mut encoded = tx.encode();
            let mut blob = vec![
                CRO_TX_AUX_ENUM_PUBLIC_TX,
                CRO_TX_AUX_PUBLIC_AUX_UNBOND_STAKE,
            ];
            blob.append(&mut encoded);
            blob
        }
        Transaction::UnjailTransaction(tx) => {
            let mut encoded = tx.encode();
            let mut blob = vec![CRO_TX_AUX_ENUM_PUBLIC_TX, CRO_TX_AUX_PUBLIC_AUX_UNJAIL];
            blob.append(&mut encoded);
            blob
        }
        Transaction::NodejoinTransaction(tx) => {
            let mut encoded = tx.encode();
            let mut blob = vec![CRO_TX_AUX_ENUM_PUBLIC_TX, CRO_TX_AUX_PUBLIC_AUX_NODE_JOIN];
            blob.append(&mut encoded);
            blob
        }
        Transaction::TransferTransaction(tx) => {
            let mut encoded = tx.encode();
            let mut blob = vec![CRO_TX_AUX_ENUM_ENCLAVE_TX, CRO_TX_AUX_ENCLAVE_TRANSFER_TX];
            blob.append(&mut encoded);
            blob
        }
        Transaction::DepositStakeTransaction(tx) => {
            let mut encoded = tx.encode();
            let mut blob = vec![CRO_TX_AUX_ENUM_ENCLAVE_TX, CRO_TX_AUX_ENCLAVE_DEPOSIT_STAKE];
            blob.append(&mut encoded);
            blob
        }
        Transaction::WithdrawUnbondedStakeTransaction(tx) => {
            let mut blob = vec![
                CRO_TX_AUX_ENUM_ENCLAVE_TX,
                CRO_TX_AUX_ENCLAVE_WITHDRAW_UNBOUNDED_STAKE,
            ];
            let mut encoded = tx.encode();
            blob.append(&mut encoded);
            blob
        }
    }
}

impl PrivateKeyAction for LedgerSignKey {
    fn sign(&self, tx: &Transaction) -> Result<RecoverableSignature> {
        let blob = get_blob(tx);
        let f = self.service.app.sign(&self.path, &blob);
        let sign_response = sync!(f, "sign failed").map_err(|e| {
            log::error!("{:?}", e);
            e
        })?;

        let recover_id = RecoveryId::from_i32(sign_response[0] as i32).chain(|| {
            (
                ErrorKind::LedgerError,
                "Invalid signature, get recover id failed",
            )
        })?;
        let sig = RecoverableSignature::from_compact(&sign_response[1..], recover_id)
            .chain(|| (ErrorKind::LedgerError, "Invalid signature"))?;
        Ok(sig)
    }

    fn schnorr_sign(&self, _tx: &Transaction) -> Result<SchnorrSignature> {
        unimplemented!("the crypto app doesn't support now, comming soon..")
    }

    fn schnorr_sign_unsafe(
        &self,
        _tx: &Transaction,
        _aux_payload: &[u8],
    ) -> Result<SchnorrSignature> {
        unreachable!()
    }

    fn public_key(&self) -> Result<PublicKey> {
        let f = self
            .service
            .app
            .get_address(&self.path, self.service.require_confirmation);
        let resp: Address = sync!(f, "get public key failed")?;
        PublicKey::deserialize_from(&resp.public_key)
    }
}
