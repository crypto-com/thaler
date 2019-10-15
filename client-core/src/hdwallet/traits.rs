/// serialization for hdwallet
pub trait Serialize<T> {
    /// serialize of hdwallet
    fn serialize(&self) -> T;
}

/// deserialization for hdwallet
pub trait Deserialize<T, E>: Sized {
    /// deserialize of hdwallet
    fn deserialize(t: T) -> Result<Self, E>;
}
