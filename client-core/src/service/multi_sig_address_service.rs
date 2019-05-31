use itertools::Itertools;
use parity_codec::{Decode, Encode};
use secp256k1::PublicKey as SecpPublicKey;
use secstr::SecUtf8;

use chain_core::common::{MerkleTree, Proof, H256};
use chain_core::tx::witness::tree::RawPubkey;
use client_common::{ErrorKind, Result, SecureStorage, Storage};

use crate::PublicKey;

const KEYSPACE: &str = "core_multi_sig_address";

/// m-of-n multi-sig address
#[derive(Debug, Encode, Decode)]
struct MultiSigAddress {
    /// Number of required co-signers
    pub m: usize,
    /// Total number of co-signers
    pub n: usize,
    /// Merkle tree with different combinations of `n` public keys as leaf nodes
    pub merkle_tree: MerkleTree<RawPubkey>,
}

/// Maintains mapping `multi-sig-public-key -> multi-sig address`
#[derive(Debug, Default, Clone)]
pub struct MultiSigAddressService<T: Storage> {
    storage: T,
}

impl<T> MultiSigAddressService<T>
where
    T: Storage,
{
    /// Creates a new instance of multi-sig address service
    pub fn new(storage: T) -> Self {
        Self { storage }
    }

    /// Creates and persists new multi-sig address
    pub fn new_multi_sig_address(
        &self,
        public_keys: Vec<PublicKey>,
        m: usize,
        n: usize,
        passphrase: &SecUtf8,
    ) -> Result<H256> {
        if m > n || public_keys.is_empty() || public_keys.len() != n {
            return Err(ErrorKind::InvalidInput.into());
        }

        let combinations = combinations(public_keys, m)?;
        let merkle_tree = MerkleTree::new(combinations);
        let root_hash = merkle_tree.root_hash();

        let multi_sig_address = MultiSigAddress { m, n, merkle_tree };

        self.storage
            .set_secure(KEYSPACE, root_hash, multi_sig_address.encode(), passphrase)?;

        Ok(root_hash)
    }

    /// Generates inclusion proof for set of addresses in multi-sig address
    pub fn generate_proof(
        &self,
        address: &H256,
        mut public_keys: Vec<PublicKey>,
        passphrase: &SecUtf8,
    ) -> Result<Proof<RawPubkey>> {
        match self.storage.get_secure(KEYSPACE, address, passphrase)? {
            None => Err(ErrorKind::AddressNotFound.into()),
            Some(address_bytes) => {
                let address = MultiSigAddress::decode(&mut address_bytes.as_slice())
                    .ok_or_else(|| client_common::Error::from(ErrorKind::DeserializationError))?;

                if public_keys.len() != address.m {
                    return Err(ErrorKind::InvalidInput.into());
                }

                public_keys.sort();

                let raw_public_key = RawPubkey::from(
                    SecpPublicKey::from(PublicKey::combine(&public_keys)?.0).serialize(),
                );

                match address.merkle_tree.generate_proof(raw_public_key) {
                    None => Err(ErrorKind::InvalidInput.into()),
                    Some(proof) => Ok(proof),
                }
            }
        }
    }

    /// Returns the number of required cosigners for given address
    pub fn required_signers(&self, address: &H256, passphrase: &SecUtf8) -> Result<usize> {
        match self.storage.get_secure(KEYSPACE, address, passphrase)? {
            None => Err(ErrorKind::AddressNotFound.into()),
            Some(address_bytes) => {
                let address = MultiSigAddress::decode(&mut address_bytes.as_slice())
                    .ok_or_else(|| client_common::Error::from(ErrorKind::DeserializationError))?;
                Ok(address.m)
            }
        }
    }

    /// Clears all storage
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }
}

fn combinations(public_keys: Vec<PublicKey>, n: usize) -> Result<Vec<RawPubkey>> {
    if public_keys.is_empty() || n > public_keys.len() {
        return Err(ErrorKind::InvalidInput.into());
    }

    let mut combinations = public_keys
        .into_iter()
        .combinations(n)
        .map(|mut combination| {
            combination.sort();
            Ok(RawPubkey::from(
                SecpPublicKey::from(PublicKey::combine(&combination)?.0).serialize(),
            ))
        })
        .collect::<Result<Vec<RawPubkey>>>()?;

    combinations.sort();
    Ok(combinations)
}

#[cfg(test)]
mod tests {
    use super::*;

    use client_common::storage::MemoryStorage;

    use crate::PrivateKey;

    #[test]
    fn check_multi_sig_address_flow() {
        let multi_sig_service = MultiSigAddressService::new(MemoryStorage::default());
        let passphrase = SecUtf8::from("passphrase");

        let public_keys = vec![
            PublicKey::from(&PrivateKey::new().unwrap()),
            PublicKey::from(&PrivateKey::new().unwrap()),
            PublicKey::from(&PrivateKey::new().unwrap()),
        ];

        assert_eq!(
            ErrorKind::InvalidInput,
            multi_sig_service
                .new_multi_sig_address(public_keys.clone(), 2, 4, &passphrase)
                .expect_err("Created invalid multi-sig address")
                .kind()
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            multi_sig_service
                .new_multi_sig_address(vec![], 0, 0, &passphrase)
                .expect_err("Created invalid multi-sig address")
                .kind()
        );

        let multi_sig_address = multi_sig_service
            .new_multi_sig_address(public_keys.clone(), 2, 3, &passphrase)
            .unwrap();

        assert_eq!(
            2,
            multi_sig_service
                .required_signers(&multi_sig_address, &passphrase)
                .unwrap()
        );

        assert_eq!(
            ErrorKind::AddressNotFound,
            multi_sig_service
                .required_signers(&[0u8; 32], &passphrase)
                .expect_err("Found non-existent address")
                .kind()
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            multi_sig_service
                .generate_proof(&multi_sig_address, public_keys.clone(), &passphrase)
                .expect_err("Generated proof for invalid signer count")
                .kind()
        );

        let proof = multi_sig_service
            .generate_proof(
                &multi_sig_address,
                vec![public_keys[0].clone(), public_keys[1].clone()],
                &passphrase,
            )
            .unwrap();

        assert!(proof.verify(&multi_sig_address));

        let rev_proof = multi_sig_service
            .generate_proof(
                &multi_sig_address,
                vec![public_keys[1].clone(), public_keys[0].clone()],
                &passphrase,
            )
            .unwrap();

        assert_eq!(proof, rev_proof);

        assert_eq!(
            ErrorKind::InvalidInput,
            multi_sig_service
                .generate_proof(
                    &multi_sig_address,
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
