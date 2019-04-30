# Crypto.com Chain Client (client-common)

This crate contains all the common types and utilities used by other `client-*` crates. These types and utilities fall
under three major categories:

- Error Handling
- Persistent Storage
- Tendermint RPC Client

### Error Handling

This crate provides an opaque error type (`Error`) returned by all the `Result`s in `client-*` crates. Besides this, it
also provides `ErrorKind` enum which has all possible variants of `Error`. It internally uses 
[`failure`](https://docs.rs/failure/0.1.5/failure/) crate.

### Data Storage

This crate defines `Storage` and `SecureStorage` trait for interacting with any storage engine. Currently, a default
implementation using [`sled`](https://docs.rs/sled/0.23.0/sled/) is provided. In addition to this, `SecureStorage` trait
provides implementation of `get_secure` and `set_secure` which should be used to store data in encrypted format.
`SecureStorage` uses [`miscreant`](https://docs.rs/miscreant/0.4.2/miscreant/) for misuse resistant symmetric 
encryption.

### Tendermint RPC Client

This crate provides `tendermint::RpcClient` which implements `Client` trait and is used to make remote calls to
tendermint nodes e.g., `genesis`, `status`, `block`, `broadcast_transaction`, etc.

## API Documentation

To see this crate's API docs. Run following command from `chain` directory.
```
cargo doc --package client-common --no-deps --open
```
