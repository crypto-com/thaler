/// Internal definitions
mod tree;

use crate::storage::Storage;
use chain_core::state::account::Account;
use rlp::{Decodable, Encodable, Rlp};
use starling::constants::KEY_LEN;
use starling::traits::{Database, Decode, Encode, Exception};
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;

/// TODO: WIP usage -- disallow dead_code when new TX types are added to work with accounts and use this
#[allow(dead_code)]
pub type AccountStorage = tree::HashTree<AccountWrapper, Storage>;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountWrapper(Account);

impl Encode for AccountWrapper {
    #[inline]
    fn encode(&self) -> Result<Vec<u8>, Exception> {
        Ok(self.0.rlp_bytes())
    }
}

impl Decode for AccountWrapper {
    #[inline]
    fn decode(buffer: &[u8]) -> Result<Self, Exception> {
        let account =
            Account::decode(&Rlp::new(buffer)).map_err(|e| Exception::new(e.description()))?;
        Ok(AccountWrapper(account))
    }
}

impl Database for Storage {
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
    fn get_node(&self, key: &[u8; KEY_LEN]) -> Result<Option<Self::NodeType>, Exception> {
        if let Some(buffer) = self.db.get(None, key).map_err(tree::convert_io_err)? {
            Ok(Some(
                Self::NodeType::decode(&Rlp::new(buffer.as_ref()))
                    .map_err(tree::convert_rlp_err)?,
            ))
        } else {
            Ok(None)
        }
    }

    #[inline]
    fn insert(&mut self, key: [u8; KEY_LEN], value: Self::NodeType) -> Result<(), Exception> {
        let serialized = value.rlp_bytes();
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
    use chain_core::init::address::RedeemAddress;
    use chain_core::state::account::Account;
    use kvdb_memorydb::create;
    use std::sync::Arc;

    fn create_db() -> Storage {
        Storage::new_db(Arc::new(create(1)))
    }

    #[test]
    fn test_account_insert_can_find() {
        let mut tree = AccountStorage::new(create_db(), 20).expect("account db");
        let account = Account::new(
            0.into(),
            0.into(),
            0.into(),
            0.into(),
            RedeemAddress::default(),
        );
        let key = account.key();
        let wrapped = AccountWrapper(account);
        let new_root = tree
            .insert(None, &mut [&key], &mut vec![&wrapped])
            .expect("insert");
        let items = tree.get(&new_root, &mut [&key]).expect("get");
        assert_eq!(items[&key], Some(wrapped));
    }

    #[test]
    fn test_account_update_can_find() {
        let mut tree = AccountStorage::new(create_db(), 20).expect("account db");
        let account = Account::new(
            0.into(),
            0.into(),
            0.into(),
            0.into(),
            RedeemAddress::default(),
        );
        let key = account.key();
        let wrapped = AccountWrapper(account);
        let old_root = tree
            .insert(None, &mut [&key], &mut vec![&wrapped])
            .expect("insert");
        let updated_account = Account::new(
            1.into(),
            1.into(),
            1.into(),
            1.into(),
            RedeemAddress::default(),
        );
        let wrapped_updated = AccountWrapper(updated_account);
        assert_ne!(wrapped, wrapped_updated);
        let new_root = tree
            .insert(Some(&old_root), &mut [&key], &mut vec![&wrapped_updated])
            .expect("insert 2");
        assert_ne!(old_root, new_root);
        let items = tree.get(&new_root, &mut [&key]).expect("get");
        assert_eq!(items[&key], Some(wrapped_updated));
        let old_items = tree.get(&old_root, &mut [&key]).expect("get 2");
        assert_eq!(old_items[&key], Some(wrapped));
    }

    #[test]
    fn test_account_remove_cannot_find() {
        let mut tree = AccountStorage::new(create_db(), 20).expect("account db");
        let account = Account::new(
            0.into(),
            0.into(),
            0.into(),
            0.into(),
            RedeemAddress::default(),
        );
        let key = account.key();
        let wrapped = AccountWrapper(account);
        let old_root = tree
            .insert(None, &mut [&key], &mut vec![&wrapped])
            .expect("insert");
        let updated_account = Account::new(
            1.into(),
            1.into(),
            1.into(),
            1.into(),
            RedeemAddress::default(),
        );
        let wrapped_updated = AccountWrapper(updated_account);
        let new_root = tree
            .insert(Some(&old_root), &mut [&key], &mut vec![&wrapped_updated])
            .expect("insert 2");
        tree.remove(&old_root).expect("remove");
        let items = tree.get(&new_root, &mut [&key]).expect("get");
        assert_eq!(items[&key], Some(wrapped_updated));
        let old_items = tree.get(&old_root, &mut [&key]).expect("get 2");
        assert_eq!(old_items[&key], None);
    }

}
