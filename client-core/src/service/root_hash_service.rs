use parity_scale_codec::{Decode, Encode};
use secstr::SecUtf8;

use chain_core::common::{Proof, H256};
use chain_core::tx::witness::tree::RawPubkey;
use client_common::{
    ErrorKind, MultiSigAddress, PublicKey, Result, ResultExt, SecureStorage, Storage,
};

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

    /// Creates and persists new multi-sig address and returns its root hash
    /// and MultiSigAddr pair
    pub fn new_root_hash(
        &self,
        public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        required_signers: usize,
        passphrase: &SecUtf8,
    ) -> Result<(H256, MultiSigAddress)> {
        let multi_sig_address =
            MultiSigAddress::new(public_keys, self_public_key, required_signers)?;
        let root_hash = multi_sig_address.root_hash();

        self.storage
            .set_secure(KEYSPACE, root_hash, multi_sig_address.encode(), passphrase)?;

        Ok((root_hash, multi_sig_address))
    }

    /// Generates inclusion proof for set of public keys in merkle root hash
    pub fn generate_proof(
        &self,
        root_hash: &H256,
        public_keys: Vec<PublicKey>,
        passphrase: &SecUtf8,
    ) -> Result<Proof<RawPubkey>> {
        let address = self.get_multi_sig_address_from_root_hash(root_hash, passphrase)?;

        address
            .generate_proof(public_keys)?
            .chain(|| (ErrorKind::InvalidInput, "Unable to generate merkle proof"))
    }

    /// Returns the number of required cosigners for given root_hash
    pub fn required_signers(&self, root_hash: &H256, passphrase: &SecUtf8) -> Result<usize> {
        let address = self.get_multi_sig_address_from_root_hash(root_hash, passphrase)?;

        Ok(address.required_signers())
    }

    /// Returns public key of current signer
    pub fn public_key(&self, root_hash: &H256, passphrase: &SecUtf8) -> Result<PublicKey> {
        let address = self.get_multi_sig_address_from_root_hash(root_hash, passphrase)?;

        Ok(address.self_public_key())
    }

    /// Returns MultiSig address from storage with the given root_hash
    /// decrypted with passphrase
    fn get_multi_sig_address_from_root_hash(
        &self,
        root_hash: &H256,
        passphrase: &SecUtf8,
    ) -> Result<MultiSigAddress> {
        let address_bytes = self
            .storage
            .get_secure(KEYSPACE, root_hash, passphrase)?
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

#[cfg(test)]
mod tests {
    use super::*;

    use secp256k1::PublicKey as SecpPublicKey;

    use client_common::storage::MemoryStorage;
    use client_common::PrivateKey;

    #[test]
    fn check_root_hash_flow() {
        let root_hash_service = RootHashService::new(MemoryStorage::default());
        let passphrase = SecUtf8::from("passphrase");

        let public_keys = vec![
            PublicKey::from(&PrivateKey::new().unwrap()),
            PublicKey::from(&PrivateKey::new().unwrap()),
            PublicKey::from(&PrivateKey::new().unwrap()),
        ];

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .new_root_hash(public_keys.clone(), public_keys[0].clone(), 5, &passphrase)
                .expect_err("Created invalid multi-sig address")
                .kind(),
            "Should throw error when required signature is larger than total public keys"
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .new_root_hash(
                    public_keys.clone(),
                    PublicKey::from(&PrivateKey::new().unwrap()),
                    2,
                    &passphrase
                )
                .expect_err("Created multi-sig address without self public key")
                .kind(),
            "Should throw error when self public key is not one of the public keys"
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .new_root_hash(vec![], public_keys[0].clone(), 0, &passphrase)
                .expect_err("Created invalid multi-sig address")
                .kind(),
            "Should throw error when required signature is 0"
        );

        let (root_hash, multi_sig_address) = root_hash_service
            .new_root_hash(public_keys.clone(), public_keys[0].clone(), 2, &passphrase)
            .unwrap();

        assert_eq!(
            2,
            root_hash_service
                .required_signers(&root_hash, &passphrase)
                .unwrap()
        );
        assert_eq!(root_hash, multi_sig_address.root_hash(),);

        assert_eq!(
            public_keys[0].clone(),
            root_hash_service
                .public_key(&root_hash, &passphrase)
                .unwrap()
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .required_signers(&[0u8; 32], &passphrase)
                .expect_err("Found non-existent address")
                .kind()
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .generate_proof(&root_hash, public_keys.clone(), &passphrase)
                .expect_err("Generated proof for invalid signer count")
                .kind()
        );

        let proof = root_hash_service
            .generate_proof(
                &root_hash,
                vec![public_keys[0].clone(), public_keys[1].clone()],
                &passphrase,
            )
            .unwrap();

        assert!(proof.verify(&root_hash));

        let rev_proof = root_hash_service
            .generate_proof(
                &root_hash,
                vec![public_keys[1].clone(), public_keys[0].clone()],
                &passphrase,
            )
            .unwrap();

        assert_eq!(proof, rev_proof);

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .generate_proof(
                    &root_hash,
                    vec![
                        public_keys[0].clone(),
                        PublicKey::from(&PrivateKey::new().unwrap())
                    ],
                    &passphrase
                )
                .expect_err("Generated proof for invalid signer count")
                .kind()
        );

        let mut signers = vec![public_keys[0].clone(), public_keys[1].clone()];
        signers.sort();

        let signer = RawPubkey::from(
            SecpPublicKey::from(PublicKey::combine(&signers).unwrap().0).serialize(),
        );

        assert_eq!(proof.value(), &signer);
    }
}
