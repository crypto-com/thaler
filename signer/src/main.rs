#![deny(missing_docs)]
//! Signer is a basic tool for secrets management (address management, transaction generation) for Crypto.com chain node.
//!
//! # Address Management
//! One of the main responsibilities of signer is address management which involves:
//! - Generation of new addresses
//! - Retreival of previously generated addresses
//! - Storage of secrets
//!
//! ## How are new addresses generated? (Note: This will change in future and we may start using HD-stype wallets)
//! - Generate a cryptographically secure random secret key. (256 bits)
//! - Derive a public key from secret key using elliptic curve cryptography. (secp256k1)
//! - Calculate address from public key depending on its type:
//!
//! 1) "RedeemAddress": Ethereum account address (for ERC20 reedem / backwards-compatibility); see `init/address.rs` in `chain-core`.
//! 2) "Tree": threshold multisig addresses; records a root of a "Merklized Abstract Syntax Tree" where branches are "OR" operations 
//! and leafs are Blake2s hashes of aggregated public keys:
//!
//! [Merklized Abstract Syntax Tree](https://blockstream.com/2015/08/24/treesignatures/)
//! [MuSig: A New Multisignature Standard](https://blockstream.com/2019/02/18/musig-a-new-multisignature-standard/)
//!
//! ### Cryptography
//! - Key operations, signatures, etc. are done via a custom fork of `rust-secp256k1` crate linked against `secp256k1zkp`
//! - `secp256k1zkp` is an experimental fork of `secp256k1` (used in Bitcoin, Ethereum, etc.) with support for new features, such as Schnorr signatures
//! - Once Schnorr signatures and MuSig are included in the upstream `secp256k1`, the tool will use the original crate
//! - Secret storage currently uses  `miscreant` (AES-SIV / AES-PMAC-SIV): this may be revised when secret storage is changed (e.g. to generate keys inside TEE enclaves)
//!
//! ## How are addresses stored?
//! Currently, signer uses `sled` crate, which is a embeddable database for Rust, to store secret keys. Addresses
//! can be derived from these secret keys.
//!
//! Before storing secret keys using `sled`, these secrets are encrypted using a misuse resistant symmetric
//! encryption crate called `miscreant`. This provides support for authenticated encryption of individual messages.
//! Encryption keys are the hashed `passphrase` provided by users at the time of address generation.
//!
//! # Signed Transaction Generation
//! Besides address management, another main responsibility of signer is to generate transactions for Crypto.com chain.
//!
//! ## Transaction Format
//! There are three main parts of a transaction:
//! - Transaction inputs (A list of previous transaction ids and their output indexes)
//! - Transaction outputs (Receiver's address, amount and timelock period)
//! - Extra attributes (chain id, etc.)
//!
//! To form a full transaction, the above data is combined with a list of witnesses (obtained by signing the transaction with witnesses' secret key)
//!

pub(crate) mod commands;
pub(crate) mod constants;
pub(crate) mod secrets;
pub(crate) mod signer;

use constants::*;
use secrets::{AddressType, Secrets};
use signer::Signer;

use failure::{Error, ResultExt};
use quest::error;
use sled::ConfigBuilder;
use sled::Db;
use structopt::StructOpt;

fn main() {
    if let Err(err) = execute() {
        error(&format!("Error: {}", err));
    }
}

fn execute() -> Result<(), Error> {
    let address_storage = Db::start(
        ConfigBuilder::new()
            .path(STORAGE_PATH.to_owned() + SECRETS_STORAGE_PATH)
            .build(),
    )
    .context("Not able to initialize secrets storage")?;

    let signer = Signer::from_args();
    signer.execute(&address_storage)
}
