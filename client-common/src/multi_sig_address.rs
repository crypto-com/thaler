//! m-of-n multi-sig address
use itertools::Itertools;
use parity_scale_codec::{Decode, Encode};

use super::{Error, ErrorKind, PublicKey, Result};
use chain_core::common::{MerkleTree, Proof, H256};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::witness::tree::RawPubkey;

// TODO: Remove pub
/// m-of-n multi-sig address
#[derive(Debug, Encode, Decode)]
pub struct MultiSigAddress {
    /// Number of required co-signers
    pub m: u64,
    /// Total number of co-signers
    pub n: u64,
    /// Public key of current signer
    pub self_public_key: PublicKey,
    /// Merkle tree with different combinations of `n` public keys as leaf nodes
    pub merkle_tree: MerkleTree<RawPubkey>,
}

impl From<MultiSigAddress> for ExtendedAddr {
    fn from(addr: MultiSigAddress) -> Self {
        addr.to_extended_addr()
    }
}

impl MultiSigAddress {
    /// Create MultiSig address from list of public keys
    pub fn new(
        public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        required_signers: usize,
    ) -> Result<Self> {
        let total_signers = public_keys.len();
        if required_signers > total_signers
            || total_signers == 0
            || required_signers == 0
            || !public_keys.contains(&self_public_key)
        {
            // TODO: Return different error kinds for different input errors
            return Err(ErrorKind::InvalidInput.into());
        }

        let combinations = public_key_combinations(public_keys, required_signers)?;
        let merkle_tree = MerkleTree::new(combinations);

        Ok(MultiSigAddress {
            m: required_signers as u64,
            n: total_signers as u64,
            self_public_key,
            merkle_tree,
        })
    }

    #[inline]
    /// Returns root hash of the underlying MerkleTree
    pub fn root_hash(&self) -> H256 {
        self.merkle_tree.root_hash()
    }

    /// Generate inclusion proof of particular public keys combination in the
    /// MultiSig address
    pub fn generate_proof(
        &self,
        mut public_keys: Vec<PublicKey>,
    ) -> Result<Option<Proof<RawPubkey>>> {
        if public_keys.len() != self.required_signers() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "{} public keys are required to generate a proof",
                    self.required_signers()
                ),
            ));
        }

        public_keys.sort();

        let raw_pubkey = PublicKey::combine_to_raw_pubkey(&public_keys)?;
        Ok(self.merkle_tree.generate_proof(raw_pubkey))
    }

    /// Returns ExtendedAddr representation of the MultiSigAddress
    #[inline]
    pub fn to_extended_addr(&self) -> ExtendedAddr {
        ExtendedAddr::OrTree(self.root_hash())
    }

    /// Returns required number of co-signers
    #[inline]
    pub fn required_signers(&self) -> usize {
        self.m as usize
    }

    /// Returns total number of co-signers
    #[inline]
    pub fn total_signers(&self) -> usize {
        self.n as usize
    }

    /// Returns self public key
    #[inline]
    pub fn self_public_key(&self) -> PublicKey {
        self.self_public_key.clone()
    }
}

fn public_key_combinations(
    public_keys: Vec<PublicKey>,
    required_signers: usize,
) -> Result<Vec<RawPubkey>> {
    if public_keys.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Length of public keys cannot be zero",
        ));
    }

    if required_signers > public_keys.len() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Length of public keys cannot be less than number of required signers",
        ));
    }

    if required_signers == 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Number of required signers cannot be zero",
        ));
    }

    let mut combinations = public_keys
        .into_iter()
        .combinations(required_signers)
        .map(|mut combination| {
            combination.sort();
            PublicKey::combine_to_raw_pubkey(&combination)
        })
        .collect::<Result<Vec<RawPubkey>>>()?;

    combinations.sort();
    Ok(combinations)
}

#[cfg(test)]
mod multi_sig_tests {
    use super::*;

    use crate::PrivateKey;

    mod generate_proof {
        use super::*;

        fn should_throw_error_when_number_of_provided_public_keys_is_different_from_required_signers(
        ) {
            let public_key_1 = PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            );
            let public_key_2 = PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            );
            let public_keys = vec![public_key_1.clone(), public_key_2.clone()];
            let required_signers = 1;

            let multi_sig_address =
                MultiSigAddress::new(public_keys, public_key_1.clone(), required_signers)
                    .expect("Should create MultiSig address");

            let target_public_keys = vec![public_key_1.clone()];
            let maybe_proof_result = multi_sig_address.generate_proof(target_public_keys);

            assert!(maybe_proof_result.is_err());
            assert_eq!(
                maybe_proof_result.unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
        }
    }

    mod new {
        use super::*;

        #[test]
        fn should_throw_error_when_public_key_list_is_empty() {
            let public_keys = Vec::new();
            let self_public_key = PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            );
            let required_signers = 1;

            let result = MultiSigAddress::new(public_keys, self_public_key, required_signers);

            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
        }

        #[test]
        fn should_throw_error_when_required_signers_is_zero() {
            let public_key = PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            );
            let public_keys = vec![public_key.clone()];
            let self_public_key = PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            );
            let required_signers = 0;

            let result = MultiSigAddress::new(public_keys, self_public_key, required_signers);

            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
        }

        #[test]
        fn should_throw_error_when_self_public_key_is_not_in_public_key_list() {
            let public_key_1 = PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            );
            let public_key_2 = PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            );
            let public_keys = vec![public_key_1.clone()];
            let required_signers = 1;

            let result = MultiSigAddress::new(public_keys, public_key_2, required_signers);

            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
        }

        #[test]
        fn should_throw_error_when_required_signers_is_greater_than_total_signers() {
            let public_key_1 = PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            );
            let public_key_2 = PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            );
            let public_keys = vec![public_key_1.clone(), public_key_2.clone()];

            let required_signers = 10;

            let result = MultiSigAddress::new(public_keys, public_key_1, required_signers);

            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
        }

        #[test]
        fn should_work() {
            let public_key_1 = PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            );
            let public_key_2 = PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            );
            let public_key_3 = PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            );
            let public_keys = vec![
                public_key_1.clone(),
                public_key_2.clone(),
                public_key_3.clone(),
            ];

            let required_signers = 2;

            let result = MultiSigAddress::new(public_keys, public_key_1, required_signers);

            assert!(result.is_ok());
        }
    }

    mod public_key_combinations {
        use super::*;

        #[test]
        fn should_throw_error_when_public_keys_is_empty() {
            let required_signers = 1;
            let result = public_key_combinations(Vec::new(), required_signers);

            assert!(result.is_err());
            assert_eq!(
                result
                    .expect_err("Length of public keys cannot be zero")
                    .kind(),
                ErrorKind::InvalidInput
            );
        }

        #[test]
        fn should_throw_error_when_required_signers_is_larger_than_total_public_keys() {
            let public_keys = vec![PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            )];
            let required_signers = 2;
            let result = public_key_combinations(public_keys, required_signers);

            assert!(result.is_err());
            assert_eq!(
                result
                    .expect_err(
                        "Length of public keys cannot be less than number of required signers"
                    )
                    .kind(),
                ErrorKind::InvalidInput
            );
        }

        #[test]
        fn should_throw_error_when_required_signers_is_zero() {
            let public_keys = vec![PublicKey::from(
                &PrivateKey::new().expect("Derive public key from private key should work"),
            )];
            let required_signers = 0;
            let result = public_key_combinations(public_keys, required_signers);

            assert!(result.is_err());
            assert_eq!(
                result
                    .expect_err("Number of required signers cannot be zero")
                    .kind(),
                ErrorKind::InvalidInput
            );
        }

        #[test]
        fn should_return_result_of_raw_pub_key_combinations() {
            // 8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bd1e8a8697ad42251de39f6a72081dfdf42abc542a6d6fe0715548b588fafbe70
            let public_key_1 = PublicKey::from(
                &PrivateKey::deserialize_from(&[0x01; 32]).expect("32 bytes, within curve order"),
            );
            // 66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4dd036ed0d31bd98c1546bb6577f852e668442060feb7c256d8b20fed0a2ad3e2a
            let public_key_2 = PublicKey::from(
                &PrivateKey::deserialize_from(&[0x02; 32]).expect("32 bytes, within curve order"),
            );
            // 37e31fcbbdbdc5c3449a7e533cc8a68fac67c827321323273d50348106e61f5358546af286730e3bd9924e52cd0f205a70ac475a67842aa81b481ee765c2929e
            let public_key_3 = PublicKey::from(
                &PrivateKey::deserialize_from(&[0x03; 32]).expect("32 bytes, within curve order"),
            );
            let public_keys = vec![
                public_key_1.clone(),
                public_key_2.clone(),
                public_key_3.clone(),
            ];

            let required_signers = 1;
            assert_eq!(
                public_key_combinations(public_keys.clone(), required_signers).unwrap(),
                vec![
                    RawPubkey::from(&public_key_2),
                    RawPubkey::from(&public_key_3),
                    RawPubkey::from(&public_key_1),
                ]
            );

            let required_signers = 2;
            assert_eq!(
                public_key_combinations(public_keys.clone(), required_signers).unwrap(),
                vec![
                    RawPubkey::from(
                        PublicKey::combine(&vec![public_key_2.clone(), public_key_1.clone()])
                            .expect("Combine public keys should work")
                            .0
                    ),
                    RawPubkey::from(
                        PublicKey::combine(&vec![public_key_3.clone(), public_key_2.clone()])
                            .expect("Combine public keys should work")
                            .0
                    ),
                    RawPubkey::from(
                        PublicKey::combine(&vec![public_key_3.clone(), public_key_1.clone()])
                            .expect("Combine public keys should work")
                            .0
                    ),
                ]
            );

            let required_signers = 3;
            assert_eq!(
                public_key_combinations(public_keys.clone(), required_signers).unwrap(),
                vec![RawPubkey::from(
                    PublicKey::combine(&vec![
                        public_key_3.clone(),
                        public_key_2.clone(),
                        public_key_1.clone()
                    ])
                    .expect("Combine public keys should work")
                    .0
                ),]
            );
        }
    }

    fn check_root_hash_flow() {
        // 8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bd1e8a8697ad42251de39f6a72081dfdf42abc542a6d6fe0715548b588fafbe70
        let public_key_1 = PublicKey::from(
            &PrivateKey::deserialize_from(&[0x01; 32]).expect("32 bytes, within curve order"),
        );
        // 66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4dd036ed0d31bd98c1546bb6577f852e668442060feb7c256d8b20fed0a2ad3e2a
        let public_key_2 = PublicKey::from(
            &PrivateKey::deserialize_from(&[0x02; 32]).expect("32 bytes, within curve order"),
        );
        // 37e31fcbbdbdc5c3449a7e533cc8a68fac67c827321323273d50348106e61f5358546af286730e3bd9924e52cd0f205a70ac475a67842aa81b481ee765c2929e
        let public_key_3 = PublicKey::from(
            &PrivateKey::deserialize_from(&[0x03; 32]).expect("32 bytes, within curve order"),
        );
        let public_keys = vec![
            public_key_1.clone(),
            public_key_2.clone(),
            public_key_3.clone(),
        ];
        let required_signers = 2;

        let multi_sig_address =
            MultiSigAddress::new(public_keys, public_key_1.clone(), required_signers)
                .expect("Should create MultiSig address");

        let target_public_keys = vec![public_key_2.clone(), public_key_1.clone()];
        let maybe_proof_result = multi_sig_address.generate_proof(target_public_keys);

        assert!(maybe_proof_result.is_ok());
        let maybe_proof = maybe_proof_result.unwrap();
        assert!(maybe_proof.is_some());
        let proof = maybe_proof.unwrap();

        let root_hash = multi_sig_address.root_hash();
        assert!(proof.verify(&root_hash));
    }
}
