use parity_scale_codec::{Decode, Encode};

use super::wallet_service::get_multisig_keyspace;
use chain_core::common::{Proof, H256};
use chain_core::tx::witness::tree::RawXOnlyPubkey;
use client_common::MultiSigAddress;
use client_common::{ErrorKind, PublicKey, Result, ResultExt, SecKey, SecureStorage, Storage};
const KEYSPACE: &str = "core_root_hash";

/// Maintains mapping `multi-sig-public-key -> multi-sig address`
#[derive(Debug, Default, Clone)]
pub struct RootHashService<T: Storage> {
    storage: T,
}

impl<T> RootHashService<T>
where
    T: Storage,
{
    /// Creates a new instance of multi-sig address service
    pub fn new(storage: T) -> Self {
        Self { storage }
    }

    /// peek new root_hash
    pub fn peek_new_root_hash(
        public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        required_signers: usize,
    ) -> Result<(H256, MultiSigAddress)> {
        let multi_sig_address =
            MultiSigAddress::new(public_keys, self_public_key, required_signers)?;

        let root_hash = multi_sig_address.root_hash();

        Ok((root_hash, multi_sig_address))
    }

    /// Creates and persists new multi-sig address and returns its root hash
    /// and MultiSigAddr pair
    pub fn new_root_hash(
        &self,
        name: &str,
        public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        required_signers: usize,
        enckey: &SecKey,
    ) -> Result<(H256, MultiSigAddress)> {
        let multi_sig_address =
            MultiSigAddress::new(public_keys, self_public_key, required_signers)?;

        let root_hash = multi_sig_address.root_hash();

        // key: roothash
        // value: multisig address info
        self.set_multi_sig_address_from_root_hash(name, enckey, &root_hash, &multi_sig_address)?;
        Ok((root_hash, multi_sig_address))
    }

    /// delete root hash
    pub fn delete_root_hash(&self, name: &str, root_hash: &H256, _enckey: &SecKey) -> Result<()> {
        let multisigaddress_keyspace = get_multisig_keyspace(name);
        self.storage
            .delete(multisigaddress_keyspace, hex::encode(&root_hash))?;
        Ok(())
    }

    /// Generates inclusion proof for set of public keys in merkle root hash
    pub fn generate_proof(
        &self,
        name: &str,
        root_hash: &H256,
        public_keys: Vec<PublicKey>,
        enckey: &SecKey,
    ) -> Result<Proof<RawXOnlyPubkey>> {
        let address = self.get_multi_sig_address_from_root_hash(name, root_hash, enckey)?;

        address
            .generate_proof(public_keys)?
            .chain(|| (ErrorKind::InvalidInput, "Unable to generate merkle proof"))
    }

    /// Returns the number of required cosigners for given root_hash
    pub fn required_signers(&self, name: &str, root_hash: &H256, enckey: &SecKey) -> Result<usize> {
        let address = self.get_multi_sig_address_from_root_hash(name, root_hash, enckey)?;

        Ok(address.required_signers())
    }

    /// Returns public key of current signer
    pub fn public_key(&self, name: &str, root_hash: &H256, enckey: &SecKey) -> Result<PublicKey> {
        let address = self.get_multi_sig_address_from_root_hash(name, root_hash, enckey)?;

        Ok(address.self_public_key())
    }

    /// store multisig address
    pub fn set_multi_sig_address_from_root_hash(
        &self,
        name: &str,
        enckey: &SecKey,
        root_hash: &H256,
        multi_sig_address: &MultiSigAddress,
    ) -> Result<()> {
        let multisigaddress_keyspace = get_multisig_keyspace(name);
        self.storage.set_secure(
            multisigaddress_keyspace,
            hex::encode(&root_hash),
            multi_sig_address.encode(),
            enckey,
        )?;
        Ok(())
    }

    /// Returns MultiSig address from storage with the given root_hash
    /// decrypted with enckey
    pub fn get_multi_sig_address_from_root_hash(
        &self,
        name: &str,
        root_hash: &H256,
        enckey: &SecKey,
    ) -> Result<MultiSigAddress> {
        let multisigaddress_keyspace = get_multisig_keyspace(name);
        let address_bytes = self
            .storage
            .get_secure(multisigaddress_keyspace, hex::encode(root_hash), enckey)?
            .chain(|| (ErrorKind::InvalidInput, "Address not found"))?;

        MultiSigAddress::decode(&mut address_bytes.as_slice()).chain(|| {
            (
                ErrorKind::DeserializationError,
                format!(
                    "Unable to deserialize multi-sig address details for root hash ({})",
                    hex::encode(root_hash)
                ),
            )
        })
    }

    /// Clears all storage
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }
}

#[cfg(all(test, feature = "experimental"))]
mod tests {
    use super::*;
    use secstr::SecUtf8;

    use client_common::storage::MemoryStorage;
    use client_common::{seckey::derive_enckey, PrivateKey};

    #[test]
    fn check_root_hash_flow() {
        let root_hash_service = RootHashService::new(MemoryStorage::default());
        let enckey = derive_enckey(&SecUtf8::from("passphrase"), "").unwrap();

        let public_keys = vec![
            PublicKey::from(&PrivateKey::new().unwrap()),
            PublicKey::from(&PrivateKey::new().unwrap()),
            PublicKey::from(&PrivateKey::new().unwrap()),
        ];
        let name = "name";

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .new_root_hash(
                    name,
                    public_keys.clone(),
                    public_keys[0].clone(),
                    5,
                    &enckey
                )
                .expect_err("Created invalid multi-sig address")
                .kind(),
            "Should throw error when required signature is larger than total public keys"
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .new_root_hash(
                    name,
                    public_keys.clone(),
                    PublicKey::from(&PrivateKey::new().unwrap()),
                    2,
                    &enckey
                )
                .expect_err("Created multi-sig address without self public key")
                .kind(),
            "Should throw error when self public key is not one of the public keys"
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .new_root_hash(name, vec![], public_keys[0].clone(), 0, &enckey)
                .expect_err("Created invalid multi-sig address")
                .kind(),
            "Should throw error when required signature is 0"
        );

        let (root_hash, multi_sig_address) = root_hash_service
            .new_root_hash(
                name,
                public_keys.clone(),
                public_keys[0].clone(),
                2,
                &enckey,
            )
            .unwrap();

        assert_eq!(
            2,
            root_hash_service
                .required_signers(name, &root_hash, &enckey)
                .unwrap()
        );
        assert_eq!(root_hash, multi_sig_address.root_hash(),);

        assert_eq!(
            public_keys[0].clone(),
            root_hash_service
                .public_key(name, &root_hash, &enckey)
                .unwrap()
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .required_signers(name, &[0u8; 32], &enckey)
                .expect_err("Found non-existent address")
                .kind()
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .generate_proof(name, &root_hash, public_keys.clone(), &enckey)
                .expect_err("Generated proof for invalid signer count")
                .kind()
        );

        let proof = root_hash_service
            .generate_proof(
                name,
                &root_hash,
                vec![public_keys[0].clone(), public_keys[1].clone()],
                &enckey,
            )
            .unwrap();

        assert!(proof.verify(&root_hash));

        let rev_proof = root_hash_service
            .generate_proof(
                name,
                &root_hash,
                vec![public_keys[1].clone(), public_keys[0].clone()],
                &enckey,
            )
            .unwrap();

        assert_eq!(proof, rev_proof);

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .generate_proof(
                    name,
                    &root_hash,
                    vec![
                        public_keys[0].clone(),
                        PublicKey::from(&PrivateKey::new().unwrap())
                    ],
                    &enckey
                )
                .expect_err("Generated proof for invalid signer count")
                .kind()
        );

        let mut signers = vec![public_keys[0].clone(), public_keys[1].clone()];
        signers.sort();

        let signer = RawXOnlyPubkey::from(combine(&signers).unwrap().0.serialize());

        assert_eq!(proof.value(), &signer);
    }
}
