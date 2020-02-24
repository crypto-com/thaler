#![allow(dead_code)]
/// TODO: WIP usage -- disallow dead_code when new TX types are added to work with accounts and use this
/// Internal definitions
mod tree;

use std::path::PathBuf;
use std::sync::Arc;

use kvdb_memorydb::create as create_memorydb;
use parity_scale_codec::{Decode as ScaleDecode, Encode as ScaleEncode};
use starling::constants::KEY_LEN;
use starling::merkle_bit::BinaryMerkleTreeResult;
use starling::traits::{Database, Decode, Encode, Exception};

use crate::Storage;
use chain_core::common::H256;
use chain_core::state::account::{to_stake_key, StakedState, StakedStateAddress};

/// key type for looking up accounts/staked states in the merkle tree storage
pub type StarlingFixedKey = [u8; KEY_LEN];

pub enum StakedStateError {
    NotFound,
    IoError(std::io::Error),
}

/// checks that the staked state can be retrieved from the trie storage
pub fn get_staked_state(
    account_address: &StakedStateAddress,
    last_root: &StarlingFixedKey,
    accounts: &AccountStorage,
) -> Result<StakedState, StakedStateError> {
    let account_key = to_stake_key(account_address);
    let account = accounts.get_one(last_root, &account_key);
    match account {
        Err(e) => Err(StakedStateError::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            e,
        ))),
        Ok(None) => Err(StakedStateError::NotFound),
        Ok(Some(AccountWrapper(a))) => Ok(a),
    }
}

/// Given the Account state storage and the current / uncommitted account storage root,
/// it inserts the updated account state into the account storage and returns the new root hash of the account state trie.
pub fn update_staked_state(
    account: StakedState,
    account_root_hash: &StarlingFixedKey,
    accounts: &mut AccountStorage,
) -> (StarlingFixedKey, Option<StakedState>) {
    (
        accounts
            .insert_one(
                Some(account_root_hash),
                &account.key(),
                &AccountWrapper(account.clone()),
            )
            .expect("update account"),
        Some(account),
    )
}

pub type AccountStorage = tree::HashTree<AccountWrapper, Storage>;

pub fn pure_account_storage(depth: usize) -> BinaryMerkleTreeResult<AccountStorage> {
    AccountStorage::new(Storage::new_db(Arc::new(create_memorydb(1))), depth)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountWrapper(pub StakedState);

impl Encode for AccountWrapper {
    #[inline]
    fn encode(&self) -> Result<Vec<u8>, Exception> {
        Ok(self.0.encode())
    }
}

impl Decode for AccountWrapper {
    #[inline]
    fn decode(buffer: &[u8]) -> Result<Self, Exception> {
        let data = Vec::from(buffer);
        let account = StakedState::decode(&mut data.as_slice())
            .map_err(|e| Exception::new(&format!("failed to decode: {}", e.what())))?;
        Ok(AccountWrapper(account))
    }
}

impl Database<H256> for Storage {
    type NodeType = tree::TreeNode;
    type EntryType = ([u8; KEY_LEN], Vec<u8>);

    #[inline]
    fn open(path: &PathBuf) -> Result<Self, Exception> {
        Ok(Storage::new_db(Arc::new(
            kvdb_rocksdb::Database::open(
                &kvdb_rocksdb::DatabaseConfig::default(),
                path.to_str().expect("invalid account db path"),
            )
            .map_err(tree::convert_io_err)?,
        )))
    }

    #[inline]
    fn get_node(&self, key: H256) -> Result<Option<Self::NodeType>, Exception> {
        if let Some(buffer) = self.db.get(0, &key).map_err(tree::convert_io_err)? {
            let data = buffer.to_vec();
            let storage = Self::NodeType::decode(&mut data.as_slice())
                .map_err(|e| Exception::new(e.what()))?;
            Ok(Some(storage))
        } else {
            Ok(None)
        }
    }

    #[inline]
    fn insert(&mut self, key: H256, value: Self::NodeType) -> Result<(), Exception> {
        let serialized = value.encode();
        let insert_tx = self.get_or_create_tx();
        insert_tx.put(0, &key, &serialized);
        Ok(())
    }

    #[inline]
    fn remove(&mut self, key: &[u8; KEY_LEN]) -> Result<(), Exception> {
        let delete_tx = self.get_or_create_tx();
        delete_tx.delete(0, key);
        Ok(())
    }

    #[inline]
    fn batch_write(&mut self) -> Result<(), Exception> {
        if let Some(dbtx) = self.current_tx.take() {
            self.db.write(dbtx).map_err(tree::convert_io_err)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use chain_core::common::Timespec;
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::state::account::{
        CouncilNode, Nonce, Punishment, PunishmentKind, StakedState, StakedStateAddress,
    };
    use chain_core::state::tendermint::TendermintValidatorPubKey;
    use kvdb_memorydb::create;
    use quickcheck::quickcheck;
    use quickcheck::Arbitrary;
    use quickcheck::Gen;
    use std::sync::Arc;

    impl Arbitrary for AccountWrapper {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let nonce: Nonce = g.next_u64();
            let bonded: u32 = g.next_u64() as u32;
            let unbonded: u32 = g.next_u64() as u32;
            let unbonded_from: Timespec = g.next_u64();
            let mut raw_address = [0u8; 20];
            g.fill_bytes(&mut raw_address);
            let address: StakedStateAddress =
                StakedStateAddress::from(RedeemAddress::from(raw_address));
            let punishment = if bool::arbitrary(g) {
                let time = u64::arbitrary(g);
                Some(Punishment {
                    kind: PunishmentKind::NonLive,
                    jailed_until: time,
                    slash_amount: None,
                })
            } else {
                None
            };
            let council_node = if bool::arbitrary(g) {
                let mut raw_pubkey = [0u8; 32];
                g.fill_bytes(&mut raw_pubkey);
                Some(CouncilNode::new(TendermintValidatorPubKey::Ed25519(
                    raw_pubkey,
                )))
            } else {
                None
            };
            AccountWrapper(StakedState {
                nonce,
                bonded: Coin::from(bonded),
                unbonded: Coin::from(unbonded),
                unbonded_from,
                address,
                punishment,
                council_node,
            })
        }
    }

    fn create_db() -> Storage {
        Storage::new_db(Arc::new(create(1)))
    }

    quickcheck! {
        // test whether insertions in different order leads to the same root hash
        fn staked_state_insert_order(accounts: Vec<AccountWrapper>) -> bool {
            let mut tree1 = AccountStorage::new(create_db(), 20).expect("account db");
            let mut tree2 = AccountStorage::new(create_db(), 20).expect("account db");
            let mut root1 = None;
            let mut root2 = None;
            for account in accounts.iter() {
                let key = account.0.key();
                let new_root = tree1.insert_one(root1.as_ref(), &key, &account).expect("insert");
                root1 = Some(new_root);
            }
            for account in accounts.iter().rev() {
                let key = account.0.key();
                let new_root = tree2.insert_one(root2.as_ref(), &key, &account).expect("insert");
                root2 = Some(new_root);
            }
            root1 == root2
        }
    }

    #[test]
    fn test_account_insert_can_find() {
        let mut tree = AccountStorage::new(create_db(), 20).expect("account db");
        let account = StakedState::default();
        let key = account.key();
        let wrapped = AccountWrapper(account);
        let new_root = tree
            .insert(None, &mut [key], &mut vec![wrapped.clone()])
            .expect("insert");
        let items = tree.get(&new_root, &mut [key]).expect("get");
        assert_eq!(items[&key], Some(wrapped));
    }

    #[test]
    fn test_account_update_can_find() {
        let mut tree = AccountStorage::new(create_db(), 20).expect("account db");
        let account = StakedState::default();
        let key = account.key();
        let wrapped = AccountWrapper(account);
        let old_root = tree
            .insert(None, &mut [key], &mut vec![wrapped.clone()])
            .expect("insert");
        let updated_account = StakedState::new(
            1,
            Coin::unit(),
            Coin::unit(),
            1,
            RedeemAddress::default().into(),
            None,
        );
        let wrapped_updated = AccountWrapper(updated_account);
        assert_ne!(wrapped, wrapped_updated);
        let new_root = tree
            .insert(
                Some(&old_root),
                &mut [key],
                &mut vec![wrapped_updated.clone()],
            )
            .expect("insert 2");
        assert_ne!(old_root, new_root);
        let items = tree.get(&new_root, &mut [key]).expect("get");
        assert_eq!(items[&key], Some(wrapped_updated));
        let old_items = tree.get(&old_root, &mut [key]).expect("get 2");
        assert_eq!(old_items[&key], Some(wrapped));
    }

    #[test]
    fn test_account_remove_cannot_find() {
        let mut tree = AccountStorage::new(create_db(), 20).expect("account db");
        let account = StakedState::default();
        let key = account.key();
        let wrapped = AccountWrapper(account);
        let old_root = tree
            .insert(None, &mut [key], &mut vec![wrapped])
            .expect("insert");
        let updated_account = StakedState::new(
            1,
            Coin::unit(),
            Coin::unit(),
            1,
            RedeemAddress::default().into(),
            None,
        );
        let wrapped_updated = AccountWrapper(updated_account);
        let new_root = tree
            .insert(
                Some(&old_root),
                &mut [key],
                &mut vec![wrapped_updated.clone()],
            )
            .expect("insert 2");
        tree.remove(&old_root).expect("remove");
        let items = tree.get(&new_root, &mut [key]).expect("get");
        assert_eq!(items[&key], Some(wrapped_updated));
        let old_items = tree.get(&old_root, &mut [key]).expect("get 2");
        assert_eq!(old_items[&key], None);
    }
}
