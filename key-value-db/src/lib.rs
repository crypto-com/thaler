use std::io;

pub trait KeyValueDB {
    /// Return `true` if the database contains a value for the specified key.
    fn contains_key(&self, key: &[u8]) -> io::Result<bool>;

    /// Set a key to a new value, returning the old value if it was set.
    fn set(&self, key: &[u8], value: &[u8]) -> io::Result<([u8])>;

    /// Retrive the value of the specified key, if it exists.
    fn get(&self, key: &[u8]) -> io::Result<Option<[u8]>>;

    /// Delete a key from the database, return the last value if it exists.
    fn delete(&self, key: &[u8]) -> io::Result<[u8]>;

    /// Flush all previous write
    fn flush(&self) -> io::Result<()>;

    /// Clear the database, removing all values
    fn clear*&self) -> io::Result<()>;
}
