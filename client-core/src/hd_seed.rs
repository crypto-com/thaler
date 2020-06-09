//! Hierarchical Deterministic seed implementing BIP39
use parity_scale_codec::{Decode, Encode};

use chain_core::init::network::{get_bip44_coin_type_from_network, Network};
use client_common::{ErrorKind, PrivateKey, PublicKey, Result, ResultExt};

use crate::hd_wallet::{
    ChainPath, DefaultKeyChain, ExtendedPrivKey, ExtendedPubKey, KeyChain, KeyIndex,
};
use crate::Mnemonic;

/// Hierarchical Deterministic seed
#[derive(Debug, Clone, PartialEq, Decode, Encode)]
pub struct HDSeed {
    /// raw data of HDSeed
    pub bytes: Vec<u8>,
}

impl From<&Mnemonic> for HDSeed {
    fn from(mnemonic: &Mnemonic) -> Self {
        HDSeed {
            bytes: mnemonic.seed().to_vec(),
        }
    }
}

impl HDSeed {
    /// Create new HD seed from seed bytes
    #[inline]
    pub fn new(bytes: Vec<u8>) -> Self {
        HDSeed { bytes }
    }

    #[inline]
    /// Returns the seed value as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derive HD wallet at specific bip44 path, and returns the key pair
    pub fn derive_key_pair(
        &self,
        network: Network,
        account_index: u32,
        index: u32,
    ) -> Result<(PublicKey, PrivateKey)> {
        let coin_type = get_bip44_coin_type_from_network(network);

        let chain_path_string = format!("m/44'/{}'/{}'/0/{}", coin_type, account_index, index);
        let chain_path = ChainPath::from(chain_path_string);
        let key_chain = DefaultKeyChain::new(
            ExtendedPrivKey::with_seed(&self.bytes)
                .chain(|| (ErrorKind::InternalError, "Invalid seed bytes"))?,
        );

        let (extended_private_key, _) = key_chain.derive_private_key(chain_path).chain(|| {
            (
                ErrorKind::InternalError,
                "Failed to derive HD wallet private key",
            )
        })?;

        let private_key = PrivateKey::from(extended_private_key.private_key);
        let public_key = PublicKey::from(&private_key);

        Ok((public_key, private_key))
    }

    /// get publickey on specific index    
    pub fn get_pubkey(
        &self,
        network: Network,
        account_index: u32,
        index: u32,
    ) -> Result<PublicKey> {
        let parent_pubkey = self.get_parent_pubkey(network, account_index)?;
        HDSeed::get_pubkey_from_parent_pubkey(&parent_pubkey, index)
    }

    /// get parent pubkey
    pub fn get_parent_pubkey(
        &self,
        network: Network,
        account_index: u32,
    ) -> Result<ExtendedPubKey> {
        let coin_type = get_bip44_coin_type_from_network(network);
        let chain_path_string = format!("m/44'/{}'/{}'/0", coin_type, account_index);
        let chain_path = ChainPath::from(chain_path_string);
        let key_chain = DefaultKeyChain::new(
            ExtendedPrivKey::with_seed(&self.bytes)
                .chain(|| (ErrorKind::InternalError, "Invalid seed bytes"))?,
        );

        let (parentkey, _) = key_chain.derive_private_key(chain_path).chain(|| {
            (
                ErrorKind::InternalError,
                "Failed to derive HD wallet private key",
            )
        })?;
        let parent_pubkey = ExtendedPubKey::from_private_key(&parentkey);
        Ok(parent_pubkey)
    }

    /// Get publickey from parent extended publickey on specific index
    pub fn get_pubkey_from_parent_pubkey(
        parent_pubkey: &ExtendedPubKey,
        index: u32,
    ) -> Result<PublicKey> {
        let pubkey = parent_pubkey
            .derive_public_key(KeyIndex::Normal(index))
            .chain(|| (ErrorKind::InternalError, "Invalid extended pubkey"))?
            .public_key;
        let public_key = PublicKey::from(pubkey);
        Ok(public_key)
    }
}

#[cfg(test)]
mod hd_seed_tests {
    use super::*;
    use crate::service::HDAccountType;
    use secstr::SecUtf8;

    #[test]
    fn same_mnemonic_words_should_restore_the_same_hd_seed() {
        let mnemonic_words = Mnemonic::new(24).expect("get 24 words mnemonics").phrase();

        let restored_hd_seed_1 = HDSeed::from(
            &Mnemonic::from_secstr(&mnemonic_words.clone())
                .expect("should restore from mnemonic words"),
        );
        let restored_hd_seed_2 = HDSeed::from(
            &Mnemonic::from_secstr(&mnemonic_words.clone())
                .expect("should restore from mnemonic words"),
        );

        assert_wallet_is_same(&restored_hd_seed_1, &restored_hd_seed_2);
    }

    mod derive_key_pair {
        use super::*;

        #[test]
        fn should_derive_at_correct_cro_path() {
            let mnemonic_words = SecUtf8::from("point shiver hurt flight fun online hub antenna engine pave chef fantasy front interest poem accident catch load frequent praise elite pet remove used");
            let mnemonic = Mnemonic::from_secstr(&mnemonic_words)
                .expect("should create mnemonic from mnemonic words");
            let hd_seed = HDSeed::from(&mnemonic);

            let expected_public_key =
                hex::decode("0396bb69cbbf27c07e08c0a9d8ac2002ed75a6287a3f2e4cfe11977817ca14fad0")
                    .expect("should decode from public key hex");
            let expected_private_key =
                hex::decode("e92a3a7859600762bca9dff4f3f3dea17b6cf1333218f38ede5b4017b54f30f5")
                    .expect("should decode from private key hex");

            let (public_key, private_key) = hd_seed
                .derive_key_pair(Network::Mainnet, HDAccountType::Transfer.index(), 1)
                .expect("should derive key pair");
            assert_eq!(expected_public_key, public_key.serialize_compressed());
            assert_eq!(expected_private_key, private_key.serialize());

            let expected_public_key =
                hex::decode("037f48caf0998415cad9b57e27d9aeaeb498324ceaf8b506eee1df31b92ee5f18b")
                    .expect("should decode from public key hex");
            let expected_private_key =
                hex::decode("0ce8339e5cb4f71903991ed7b1e12b09a7e7904b5926eb22c7f7c0afdddd6f5a")
                    .expect("should decode from private key hex");

            let (public_key, private_key) = hd_seed
                .derive_key_pair(Network::Devnet, HDAccountType::Staking.index(), 1)
                .expect("should derive key pair");
            assert_eq!(expected_public_key, public_key.serialize_compressed());
            assert_eq!(expected_private_key, private_key.serialize());
        }
    }

    fn assert_wallet_is_same(wallet: &HDSeed, other: &HDSeed) {
        assert_eq!(wallet.as_bytes(), other.as_bytes());
    }

    #[test]
    fn should_get_publickey_return_correct_key() {
        let mnemonic_words = SecUtf8::from("point shiver hurt flight fun online hub antenna engine pave chef fantasy front interest poem accident catch load frequent praise elite pet remove used");
        let mnemonic = Mnemonic::from_secstr(&mnemonic_words)
            .expect("should create mnemonic from mnemonic words");
        let hd_seed = HDSeed::from(&mnemonic);
        let expected_public_key =
            hex::decode("0396bb69cbbf27c07e08c0a9d8ac2002ed75a6287a3f2e4cfe11977817ca14fad0")
                .expect("should decode from public key hex");
        let expected_private_key =
            hex::decode("e92a3a7859600762bca9dff4f3f3dea17b6cf1333218f38ede5b4017b54f30f5")
                .expect("should decode from private key hex");

        let (public_key, private_key) = hd_seed
            .derive_key_pair(Network::Mainnet, HDAccountType::Transfer.index(), 1)
            .expect("should derive key pair");
        assert_eq!(expected_public_key, public_key.serialize_compressed());
        assert_eq!(expected_private_key, private_key.serialize());
        let pubkey = hd_seed
            .get_pubkey(Network::Mainnet, HDAccountType::Transfer.index(), 1)
            .expect("get_publickey");
        assert_eq!(pubkey.serialize_compressed(), expected_public_key);

        let parent_pubkey = hd_seed
            .get_parent_pubkey(Network::Mainnet, HDAccountType::Transfer.index())
            .unwrap();

        for i in 0..256 {
            let pubkey = HDSeed::get_pubkey_from_parent_pubkey(&parent_pubkey, i)
                .unwrap()
                .serialize();
            assert_eq!(
                hd_seed
                    .derive_key_pair(Network::Mainnet, HDAccountType::Transfer.index(), i)
                    .unwrap()
                    .0
                    .serialize(),
                pubkey
            );
        }
    }
}
