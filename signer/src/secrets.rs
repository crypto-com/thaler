use failure::Error;
use hex::encode;
use rand::rngs::OsRng;
use secp256k1zkp::aggsig::{add_signatures_single, export_secnonce_single, sign_single};
use secp256k1zkp::key::{PublicKey, SecretKey};
use secp256k1zkp::{Message, Secp256k1};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use structopt::clap::{_clap_count_exprs, arg_enum};
use zeroize::Zeroize;

use chain_core::tx::witness::redeem::EcdsaSignature;
use chain_core::tx::witness::tree::{pk_to_raw, sig_to_raw};
use chain_core::tx::witness::TxInWitness;

arg_enum! {
    /// Different address types
    #[derive(Debug)]
    pub enum AddressType {
        Spend,
        View,
    }
}

/// Struct for specifying secrets
#[derive(Serialize, Deserialize, Debug)]
pub struct Secrets {
    #[serde(skip, default = "Secp256k1::new")]
    secp: Secp256k1,

    pub spend: SecretKey,
    pub view: SecretKey,
}

impl Secrets {
    /// Generates random spend and view secret keys
    pub fn generate() -> Result<Secrets, Error> {
        let mut rand = OsRng::new()?;
        let mut secp = Secp256k1::new();

        let spend = SecretKey::new(&secp, &mut rand);

        secp.randomize(&mut rand);

        let view = SecretKey::new(&secp, &mut rand);

        Ok(Secrets { secp, spend, view })
    }

    /// Returns public key derived from current secret key of given address type
    pub fn get_public_key(&self, address_type: AddressType) -> Result<PublicKey, Error> {
        use AddressType::*;

        match address_type {
            Spend => Ok(PublicKey::from_secret_key(&self.secp, &self.spend)?),
            View => Ok(PublicKey::from_secret_key(&self.secp, &self.view)?),
        }
    }

    /// Returns address derived from current secret key of given address type
    pub fn get_address(&self, address_type: AddressType) -> Result<String, Error> {
        let public_key = self.get_public_key(address_type)?;

        let mut hasher = Keccak256::new();
        hasher.input(&public_key.serialize_vec(&self.secp, false)[1..]);
        let hash = hasher.result()[12..].to_vec();

        Ok(encode(hash))
    }

    /// Returns ECDSA signature of message signed with provided secret
    pub fn get_ecdsa_signature(&self, message: &Message) -> Result<TxInWitness, Error> {
        let signature = self.secp.sign_recoverable(message, &self.spend)?;
        let (recovery_id, serialized_signature) = signature.serialize_compact(&self.secp);

        let r = &serialized_signature[0..32];
        let s = &serialized_signature[32..64];
        let mut sign = EcdsaSignature::default();

        sign.v = recovery_id.to_i32() as u8;
        sign.r.copy_from_slice(r);
        sign.s.copy_from_slice(s);

        Ok(TxInWitness::BasicRedeem(sign))
    }

    /// Returns 2-of-2 (view+spend keys) agg/combined Schonrr signature of message signed with provided secret
    /// TODO: "All aggsig-related api functions need review and are subject to change."
    /// TODO: migrate to https://github.com/ElementsProject/secp256k1-zkp/pull/35
    /// WARNING: secp256k1-zkp was/is highly experimental, its implementation should be verified or replaced by more stable and audited library (when available)
    pub fn get_schnorr_signature(&self, message: &Message) -> Result<TxInWitness, Error> {
        use AddressType::*;

        let spend_public_key = self.get_public_key(Spend)?;
        let view_public_key = self.get_public_key(View)?;

        let secnonce_1 = export_secnonce_single(&self.secp)?;
        let secnonce_2 = export_secnonce_single(&self.secp)?;
        let pubnonce_2 = PublicKey::from_secret_key(&self.secp, &secnonce_2)?;
        let mut nonce_sum = pubnonce_2;
        nonce_sum.add_exp_assign(&self.secp, &secnonce_1)?;
        let mut pk_sum = view_public_key;
        pk_sum.add_exp_assign(&self.secp, &self.spend)?;
        let sig1 = sign_single(
            &self.secp,
            &message,
            &self.spend,
            Some(&secnonce_1),
            None,
            Some(&nonce_sum),
            Some(&pk_sum),
            Some(&nonce_sum),
        )?;
        let sig2 = sign_single(
            &self.secp,
            &message,
            &self.view,
            Some(&secnonce_2),
            None,
            Some(&nonce_sum),
            Some(&pk_sum),
            Some(&nonce_sum),
        )?;
        let sig = add_signatures_single(&self.secp, vec![&sig1, &sig2], &nonce_sum)?;
        let pk =
            PublicKey::from_combination(&self.secp, vec![&spend_public_key, &view_public_key])?;

        Ok(TxInWitness::TreeSig(
            pk_to_raw(&self.secp, pk),
            sig_to_raw(&self.secp, sig),
            vec![],
        ))
    }
}

impl Drop for Secrets {
    fn drop(&mut self) {
        self.spend.0.zeroize();
        self.view.0.zeroize();
    }
}
