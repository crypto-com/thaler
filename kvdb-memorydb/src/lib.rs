use kvdb::{Error, KeyValueDB};
use std::collections::HashMap;

pub struct MemoryDB {
    map: HashMap<Vec<u8>, HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryDB {
    pub fn new() -> MemoryDB {
        MemoryDB {
            map: HashMap::new(),
        }
    }
}

impl KeyValueDB for MemoryDB {
    fn contains_column(&self, col: &[u8]) -> bool {
        self.map.contains_key(col)
    }

    fn column_contains_key(&self, column: &[u8], key: &[u8]) -> bool {
        match self.map.get(column) {
            Some(column_map) => column_map.contains_key(key),
            None => false,
        }
    }

    /// Set a key to a new value, returning the old value if it was set.
    fn set(&mut self, column: &[u8], key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let column_map = match self.map.get_mut(column) {
            None => {
                self.map.insert(column.to_vec(), HashMap::new());
                self.map.get_mut(column).unwrap()
            }
            Some(map) => map,
        };

        let old_value = column_map.get(key).map(|x| x.clone());
        column_map.insert(key.to_vec(), value.to_vec());
        Ok(old_value)
    }

    /// Retrive the value of the key. If the key does not exist return None.
    /// An error is returned when the column does not exist
    fn get(&self, column: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self.map.get(column) {
            None => Err(Error::from(kvdb::ErrorKind::ColumnNotFound)),
            Some(column_map) => Ok(column_map.get(key).cloned()),
        }
    }

    /// Delete a key from the database, return the last value if it exists.
    /// An error is returned when the column does not exist
    fn delete(&mut self, column: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self.map.get_mut(column) {
            None => Err(Error::from(kvdb::ErrorKind::ColumnNotFound)),
            Some(column_map) => {
                let old_value = column_map.get(key).cloned();
                column_map.remove(key);
                Ok(old_value)
            }
        }
    }

    /// Flush all previous write
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Clear the database, removing all values
    fn clear(&mut self) -> Result<(), Error> {
        self.map.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    mod get {
        use crate::*;

        #[test]
        #[should_panic(expected = "Column not found")]
        fn should_panic_missing_column_error_when_column_does_not_exist() {
            let memory_db = MemoryDB::new();

            let unexist_column = "Unexist Column".as_bytes();
            let key = "Key".as_bytes();
            memory_db.get(unexist_column, key).unwrap();
        }

        #[test]
        fn should_return_none_when_key_does_not_exist() {
            let mut memory_db = MemoryDB::new();

            let column = "Column".as_bytes();
            let key = "Key".as_bytes();
            let value = "Value".as_bytes();
            memory_db.set(column, key, value).unwrap();

            let unexist_key = "Unexist Key".as_bytes();
            assert_eq!(memory_db.get(column, unexist_key).unwrap(), None);
        }

        #[test]
        fn should_return_the_value_in_column_and_key() {
            let mut memory_db = MemoryDB::new();

            let column = "Column".as_bytes();
            let key = "Key".as_bytes();
            let value = String::from("Value");
            memory_db.set(column, key, value.as_bytes()).unwrap();

            assert_eq!(
                memory_db.get(column, key).unwrap(),
                Some(value.into_bytes())
            );
        }
    }

    mod set {
        use crate::*;

        #[test]
        fn set_should_set_a_key_with_the_value() {
            let mut memory_db = MemoryDB::new();
            let column = String::from("Column");
            let key = String::from("Key");
            let value = String::from("Value");
            memory_db
                .set(column.as_bytes(), key.as_bytes(), value.as_bytes())
                .unwrap();

            assert_eq!(
                memory_db.get(column.as_bytes(), key.as_bytes()).unwrap(),
                Some(value.into_bytes())
            );
        }

        #[test]
        fn set_should_overwrite_a_key_with_new_value() {
            let mut memory_db = MemoryDB::new();
            let column = "Column".as_bytes();
            let key = "Key".as_bytes();
            let value = "Value".as_bytes();
            memory_db.set(column, key, value).unwrap();

            let new_value = String::from("New Value");
            memory_db.set(column, key, new_value.as_bytes()).unwrap();

            assert_eq!(
                memory_db.get(column, key).unwrap(),
                Some(new_value.into_bytes())
            );
        }

        #[test]
        fn set_should_return_overwritten_value_if_exist() {
            let mut memory_db = MemoryDB::new();
            let column = "Column".as_bytes();
            let key = "Key".as_bytes();
            let expected_old_value = String::from("Value");
            memory_db
                .set(column, key, expected_old_value.as_bytes())
                .unwrap();

            let new_value = String::from("New Value");
            let actual_old_value = memory_db.set(column, key, new_value.as_bytes()).unwrap();

            assert_eq!(actual_old_value, Some(expected_old_value.into_bytes()));
        }
    }

    mod delete {
        use crate::*;

        #[test]
        #[should_panic(expected = "Column not found")]
        fn should_panic_missing_column_error_when_column_does_not_exist() {
            let mut memory_db = MemoryDB::new();

            let unexist_column = "Unexist Column".as_bytes();
            let key = "Key".as_bytes();
            memory_db.delete(unexist_column, key).unwrap();
        }

        #[test]
        fn should_return_none_when_key_does_not_exist() {
            let mut memory_db = MemoryDB::new();

            let column = "Column".as_bytes();
            let key = "Key".as_bytes();
            let value = "Value".as_bytes();
            memory_db.set(column, key, value).unwrap();

            let unexist_key = "Unexist Key".as_bytes();
            assert_eq!(memory_db.delete(column, unexist_key).unwrap(), None);
        }

        #[test]
        fn should_delete_key() {
            let mut memory_db = MemoryDB::new();

            let column = "Column".as_bytes();
            let key = "Key".as_bytes();
            let value = "Value".as_bytes();
            memory_db.set(column, key, value).unwrap();

            memory_db.delete(column, key).unwrap();

            assert_eq!(memory_db.get(column, key).unwrap(), None);
        }

        #[test]
        fn should_return_deleted_key_if_exist() {
            let mut memory_db = MemoryDB::new();

            let column = "Column".as_bytes();
            let key = "Key".as_bytes();
            let value = "Value".as_bytes();
            memory_db.set(column, key, value).unwrap();

            assert_eq!(memory_db.delete(column, key).unwrap(), Some(value.to_vec()));
        }
    }

    mod clear {
        use crate::*;

        #[test]
        fn should_clear_everything() {
            let mut memory_db = MemoryDB::new();

            let column = "Column One".as_bytes();
            let value = "Value".as_bytes();
            memory_db.set(column, "Key".as_bytes(), value).unwrap();
            memory_db.set(column, "Key2".as_bytes(), value).unwrap();
            memory_db.set(column, "Key3".as_bytes(), value).unwrap();
            memory_db.set(column, "Key4".as_bytes(), value).unwrap();

            memory_db.clear().unwrap();

            assert_eq!(memory_db.contains_column(column), false);
        }
    }
}
