#![allow(dead_code)]
/// TODO: WIP usage -- disallow dead_code when new TX types are added to work with accounts and use this
/// Internal definitions
mod tree;

use crate::storage::Storage;
use chain_core::common::H256;
use chain_core::state::account::StakedState;
use parity_scale_codec::{Decode as ScaleDecode, Encode as ScaleEncode};
use starling::constants::KEY_LEN;
use starling::traits::{Database, Decode, Encode, Exception};
use std::path::PathBuf;
use std::sync::Arc;

pub type AccountStorage = tree::HashTree<AccountWrapper, Storage>;

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
            kvdb_rocksdb::Database::open_default(path.to_str().expect("invalid account db path"))
                .map_err(tree::convert_io_err)?,
        )))
    }

    #[inline]
    fn get_node(&self, key: H256) -> Result<Option<Self::NodeType>, Exception> {
        if let Some(buffer) = self.db.get(None, &key).map_err(tree::convert_io_err)? {
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
        let mut insert_tx = self.db.transaction();
        insert_tx.put(None, &key, &serialized);
        // this "buffered write" shouldn't persist (persistence done in batch write)
        // but should change it in-memory -- TODO: check
        self.db.write_buffered(insert_tx);
        Ok(())
    }

    #[inline]
    fn remove(&mut self, key: &[u8; KEY_LEN]) -> Result<(), Exception> {
        let mut delete_tx = self.db.transaction();
        delete_tx.delete(None, key);
        self.db.write_buffered(delete_tx);
        Ok(())
    }

    #[inline]
    fn batch_write(&mut self) -> Result<(), Exception> {
        self.db.flush().map_err(tree::convert_io_err)
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use chain_core::common::Timespec;
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::state::account::Nonce;
    use chain_core::state::account::StakedState;
    use chain_core::state::account::StakedStateAddress;
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
            let unbonded_from: Timespec = g.next_u64() as i64;
            let mut raw_address = [0u8; 20];
            g.fill_bytes(&mut raw_address);
            let address: StakedStateAddress =
                StakedStateAddress::from(RedeemAddress::from(raw_address));
            AccountWrapper(StakedState {
                nonce,
                bonded: Coin::from(bonded),
                unbonded: Coin::from(unbonded),
                unbonded_from,
                address,
                punishment: None,
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
