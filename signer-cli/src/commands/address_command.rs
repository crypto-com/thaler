use bincode::{deserialize, serialize};
use blake2::{Blake2s, Digest};
use failure::{format_err, Error, ResultExt};
use miscreant::{Aead, Aes128PmacSivAead};
use quest::{ask, password, success};
use rand::rngs::OsRng;
use rand::Rng;
use sled::Db;
use structopt::StructOpt;
use zeroize::Zeroize;

use signer_core::{AddressType, Secrets};

/// Nonce size in bytes
pub const NONCE_SIZE: usize = 8;

/// Enum used to specify different subcommands under address command.
/// Refer to main documentation for algorithm to generate new addresses.
#[derive(Debug, StructOpt)]
pub enum AddressCommand {
    /// Used to generate a new address
    #[structopt(name = "generate", about = "Generate new address")]
    Generate {
        #[structopt(name = "name", short, long, help = "Name of address")]
        name: String,
    },
    /// Used to retrieve a previously generated address
    #[structopt(name = "get", about = "Get a address")]
    Get {
        #[structopt(name = "name", short, long, help = "Name of address")]
        name: String,
        #[structopt(name = "type", short, long, help = "Type of address (spend or view)")]
        address_type: Option<AddressType>,
    },
    /// Used to list all previously generated address names
    #[structopt(name = "list", about = "List all addresses")]
    List,
    /// Used to clear address storage
    #[structopt(name = "clear", about = "Clear all stored addresses")]
    Clear,
}

impl AddressCommand {
    /// Executes current address command
    pub fn execute(&self, address_storage: &Db) -> Result<(), Error> {
        use AddressCommand::*;

        match self {
            Generate { name } => Self::generate(name, address_storage),
            Get { name, address_type } => Self::get(name, address_type, address_storage),
            List => Self::list(address_storage),
            Clear => Self::clear(address_storage),
        }
    }

    /// Clears address storage
    fn clear(address_storage: &Db) -> Result<(), Error> {
        address_storage
            .clear()
            .context("Unable to clear address storage")?;

        success("Cleared address storage");

        Ok(())
    }

    /// Returns the encryptor/decryptor for passphrase entered by user
    fn get_algo() -> Result<Aes128PmacSivAead, Error> {
        ask("Enter passphrase: ");

        let mut hasher = Blake2s::new();
        hasher.input(password()?);

        let mut passphrase = hasher.result_reset();

        let algo = Aes128PmacSivAead::new(&passphrase);

        passphrase.zeroize();

        Ok(algo)
    }

    /// Returns secrets for a given name
    pub fn get_secrets(name: &str, address_storage: &Db) -> Result<Secrets, Error> {
        let key = serialize(name).context("Unable to serialize key")?;

        match address_storage
            .get(key)
            .context("Unable to connect to storage")?
        {
            None => Err(format_err!("No address found with name: {}!", name)),
            Some(value) => {
                let nonce_index = value.len() - NONCE_SIZE;

                let mut algo = Self::get_algo()?;

                Ok(deserialize(
                    &algo
                        .open(
                            &value[nonce_index..],
                            name.as_bytes(),
                            &value[..nonce_index],
                        )
                        .context("Unable to decrypt secrets")?,
                )
                .context("Unable to deserialize secrets")?)
            }
        }
    }

    /// Generates a secrets and stores them in storage after encryption
    fn generate(name: &str, address_storage: &Db) -> Result<(), Error> {
        if address_storage
            .contains_key(name)
            .context("Unable to connect to storage")?
        {
            Err(format_err!("Address with name: {} already exists", name))
        } else {
            let mut algo = Self::get_algo()?;
            let secrets = Secrets::generate()?;

            let mut nonce = [0u8; NONCE_SIZE];
            let mut rand = OsRng::new()?;
            rand.fill(&mut nonce);

            let mut cipher = algo.seal(
                &nonce,
                name.as_bytes(),
                &serialize(&secrets).context("Unable to serialize secrets")?,
            );
            cipher.extend(&nonce[..]);

            address_storage
                .set(serialize(name).context("Unable to serialize name")?, cipher)
                .context("Unable to store secrets")?;

            success(&format!("Address generated for name: {}", name));
            Ok(())
        }
    }

    /// Retrieves address for a given name and type from storage
    fn get(
        name: &str,
        address_type: &Option<AddressType>,
        address_storage: &Db,
    ) -> Result<(), Error> {
        use AddressType::*;

        let secrets = Self::get_secrets(name, address_storage)?;

        if let Some(address_type) = address_type {
            match address_type {
                Spend => {
                    ask("Spend address: ");
                    success(&secrets.get_address(Spend)?);
                }
                View => {
                    ask("View address: ");
                    success(&secrets.get_address(View)?);
                }
            }
        } else {
            ask("Spend address: ");
            success(&secrets.get_address(Spend)?);

            ask("View address: ");
            success(&secrets.get_address(View)?);
        }

        Ok(())
    }

    /// Lists all address names
    fn list(address_storage: &Db) -> Result<(), Error> {
        let keys = address_storage.iter().keys();

        let result: Result<Vec<_>, _> = keys
            .map(|key| -> Result<(), Error> {
                let key: String = deserialize(&key.context("Pagecache error")?)
                    .context("Unable to deserialize key")?;
                ask("Key name: ");
                success(&key);
                Ok(())
            })
            .collect();

        if let Err(err) = result {
            Err(err)
        } else {
            Ok(())
        }
    }
}
