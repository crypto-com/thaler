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
//! - Calculate address from public key.
//!
//! ### Generating Secret Keys
//! Signer uses `grin_secp256k1zkp` crate to generate cryptographically secure random secret keys.
//! NOTE: Subject to change when secp256k1 includes Schnorr signature-related features.
//!
//! ### Generating Public Keys
//! Again, signer uses `grin_secp256k1zkp` crate to derive public keys from secret keys.
//!
//! ### Generating Chain Address
//! There are three main steps to obtain chain address from public keys
//! - Start with the public key. (64 bytes)
//! - Take a Keccak-256 hash of public key. (Note: Keccak-256 is different from SHA3-256. [Difference between Keccak256 and SHA3-256](https://ethereum.stackexchange.com/questions/30369/difference-between-keccak256-and-sha3) ) (32 bytes)
//! - Take the last 20 bytes of this Keccak-256 hash. Or, in other words, drop the first 12 bytes.
//!   These 20 bytes are the address.
//!
//! [Recommended Read](https://kobl.one/blog/create-full-ethereum-keypair-and-address/)
//!
//! ## How are addresses stored?
//! Currently, signer uses `sled` crate, which is a embeddable database for Rust, to store secret keys. Addresses
//! can be derived from these secret keys.
//!
//! Before storing secret keys using `sled`, these secrets are encrypted using a misuse resistant symmetric
//! encryption crate called `miscreant`. This provides support for authenticated encryption of individual messages.
//! Encryption keys are the `passphrase` provided by users at the time of address geneation.
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
