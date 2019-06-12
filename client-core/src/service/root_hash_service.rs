use itertools::Itertools;
use parity_codec::{Decode, Encode};
use secstr::SecUtf8;

use chain_core::common::{MerkleTree, Proof, H256};
use chain_core::tx::witness::tree::RawPubkey;
use client_common::{Error, ErrorKind, Result, SecureStorage, Storage};

use crate::PublicKey;

const KEYSPACE: &str = "core_root_hash";

/// m-of-n multi-sig address
#[derive(Debug, Encode, Decode)]
struct MultiSigAddress {
    /// Number of required co-signers
    pub m: u64,
    /// Total number of co-signers
    pub n: u64,
    /// Public key of current signer
    pub self_public_key: PublicKey,
    /// Merkle tree with different combinations of `n` public keys as leaf nodes
    pub merkle_tree: MerkleTree<RawPubkey>,
}

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
    pub fn new_root_hash(
        &self,
        public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        m: usize,
        n: usize,
        passphrase: &SecUtf8,
    ) -> Result<H256> {
        if m > n
            || public_keys.is_empty()
            || public_keys.len() != n
            || m == 0
            || !public_keys.contains(&self_public_key)
        {
            // TODO: Return different error kinds for different input errors
            return Err(ErrorKind::InvalidInput.into());
        }

        let combinations = combinations(public_keys, m)?;
        let merkle_tree = MerkleTree::new(combinations);
        let root_hash = merkle_tree.root_hash();

        let multi_sig_address = MultiSigAddress {
            m: m as u64,
            n: n as u64,
            self_public_key,
            merkle_tree,
        };

        self.storage
            .set_secure(KEYSPACE, root_hash, multi_sig_address.encode(), passphrase)?;

        Ok(root_hash)
    }

    /// Generates inclusion proof for set of public keys in merkle root hash
    pub fn generate_proof(
        &self,
        root_hash: &H256,
        mut public_keys: Vec<PublicKey>,
        passphrase: &SecUtf8,
    ) -> Result<Proof<RawPubkey>> {
        let address_bytes = self
            .storage
            .get_secure(KEYSPACE, root_hash, passphrase)?
            .ok_or_else(|| Error::from(ErrorKind::AddressNotFound))?;
        let address = MultiSigAddress::decode(&mut address_bytes.as_slice())
            .ok_or_else(|| Error::from(ErrorKind::DeserializationError))?;

                if public_keys.len() != address.m as usize {
                    return Err(ErrorKind::InvalidInput.into());
                }

        public_keys.sort();

        address
            .merkle_tree
            .generate_proof(raw_public_key(&public_keys)?)
            .ok_or_else(|| Error::from(ErrorKind::InvalidInput))
    }

    /// Returns the number of required cosigners for given root_hash
    pub fn required_signers(&self, root_hash: &H256, passphrase: &SecUtf8) -> Result<usize> {
        let address_bytes = self
            .storage
            .get_secure(KEYSPACE, root_hash, passphrase)?
            .ok_or_else(|| Error::from(ErrorKind::AddressNotFound))?;

        let address = MultiSigAddress::decode(&mut address_bytes.as_slice())
            .ok_or_else(|| Error::from(ErrorKind::DeserializationError))?;

        Ok(address.m as usize)
    }  

    /// Returns public key of current signer
    pub fn public_key(&self, root_hash: &H256, passphrase: &SecUtf8) -> Result<PublicKey> {
        let address_bytes = self
            .storage
            .get_secure(KEYSPACE, root_hash, passphrase)?
            .ok_or_else(|| Error::from(ErrorKind::AddressNotFound))?;

        let address = MultiSigAddress::decode(&mut address_bytes.as_slice())
            .ok_or_else(|| client_common::Error::from(ErrorKind::DeserializationError))?;

        Ok(address.self_public_key)
    }

    /// Clears all storage
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }
}

fn raw_public_key(public_keys: &[PublicKey]) -> Result<RawPubkey> {
    if public_keys.len() == 1 {
        Ok(RawPubkey::from(&public_keys[0]))
    } else {
        Ok(RawPubkey::from(PublicKey::combine(&public_keys)?.0))
    }
}

fn combinations(public_keys: Vec<PublicKey>, n: usize) -> Result<Vec<RawPubkey>> {
    if public_keys.is_empty() || n > public_keys.len() || n == 0 {
        return Err(ErrorKind::InvalidInput.into());
    }

    let mut combinations = public_keys
        .into_iter()
        .combinations(n)
        .map(|mut combination| {
            combination.sort();
            raw_public_key(&combination)
        })
        .collect::<Result<Vec<RawPubkey>>>()?;

    combinations.sort();
    Ok(combinations)
}

#[cfg(test)]
mod tests {
    use super::*;

    use secp256k1::PublicKey as SecpPublicKey;

    use client_common::storage::MemoryStorage;

    use crate::PrivateKey;

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
                .new_root_hash(
                    public_keys.clone(),
                    public_keys[0].clone(),
                    2,
                    4,
                    &passphrase
                )
                .expect_err("Created invalid multi-sig address")
                .kind()
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .new_root_hash(
                    public_keys.clone(),
                    PublicKey::from(&PrivateKey::new().unwrap()),
                    2,
                    3,
                    &passphrase
                )
                .expect_err("Created multi-sig address without self public key")
                .kind()
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            root_hash_service
                .new_root_hash(vec![], public_keys[0].clone(), 0, 0, &passphrase)
                .expect_err("Created invalid multi-sig address")
                .kind()
        );

        let root_hash = root_hash_service
            .new_root_hash(
                public_keys.clone(),
                public_keys[0].clone(),
                2,
                3,
                &passphrase,
            )
            .unwrap();

        assert_eq!(
            2,
            root_hash_service
                .required_signers(&root_hash, &passphrase)
                .unwrap()
        );

        assert_eq!(
            public_keys[0].clone(),
            root_hash_service
                .public_key(&root_hash, &passphrase)
                .unwrap()
        );

        assert_eq!(
            ErrorKind::AddressNotFound,
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
