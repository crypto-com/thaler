//! # Extended Key for HD-wallet
//! adapted from https://github.com/jjyr/hdwallet (HDWallet)
//! Copyright (c) 2018, Jiang Jinyang (licensed under the MIT License)
//! Modifications Copyright (c) 2018 - 2019, Foris Limited (licensed under the Apache License, Version 2.0)
//!

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
