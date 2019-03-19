mod error;

pub use error::{Error, ErrorKind};

pub trait KeyValueDB {
    /// Set a key to a new value, returning the old value if it was set.
    fn set(&mut self, column: &[u8], key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    /// Return `true` if the database contains a value for the specified column.
    fn contains_column(&self, column: &[u8]) -> bool;

    /// Return `true` if the database contains a value for the specified column
    /// and key.
    fn column_contains_key(&self, column: &[u8], key: &[u8]) -> bool;

    /// Retrive the value of the key. If the key does not exist return None.
    /// An error is returned when the column does not exist
    fn get(&self, column: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    /// Delete a key from the database, return the last value if it exists.
    /// An error is returned when the column does not exist
    fn delete(&mut self, column: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    /// Flush all previous write
    fn flush(&mut self) -> Result<(), Error>;

    /// Clear the database, removing all values
    fn clear(&mut self) -> Result<(), Error>;
}
