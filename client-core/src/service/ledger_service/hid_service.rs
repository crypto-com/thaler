use crate::hd_wallet::ChainPath;
use crate::service::hw_key_service::HardwareWalletAction;
use crate::service::ledger_service::get_blob;
use crate::sync;
use client_common::{
    Error, ErrorKind, PrivateKeyAction, PublicKey, Result, ResultExt, Transaction,
};
use ledger_crypto::{APDUTransport, Address, CryptoApp};
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use secp256k1::schnorrsig::SchnorrSignature;
use std::sync::Arc;
use tokio::runtime::Runtime;
use zx_bip44::BIP44Path;

/// Hedger Service
#[derive(Clone)]
pub struct LedgerServiceHID {
    /// crypto app of ledger
    pub app: Arc<CryptoApp<ledger::TransportNativeHID>>,
    /// confirmation on ledger or not
    pub require_confirmation: bool,
}

impl std::fmt::Debug for LedgerServiceHID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerService")
            .field("app", &"CryptoApp")
            .field("require_confirmation", &self.require_confirmation)
            .finish()
    }
}

impl LedgerServiceHID {
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

impl HardwareWalletAction for LedgerServiceHID {
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
        let hw_key = LedgerSignKeyHID {
            path,
            service: self.clone(),
        };
        Ok(Box::new(hw_key))
    }
}

/// represent a private key, can sign msg in the ledger device with `path` using `service`
pub struct LedgerSignKeyHID {
    path: BIP44Path,
    service: LedgerServiceHID,
}

impl PrivateKeyAction for LedgerSignKeyHID {
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
