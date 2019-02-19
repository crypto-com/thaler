use bincode::{deserialize, serialize};
use blake2::{Blake2s, Digest};
use failure::{format_err, Error, ResultExt};
use hex::encode;
use miscreant::{Aead, Aes128PmacSivAead};
use quest::{ask, password, success};
use rand::rngs::OsRng;
use rand::Rng;
use secp256k1zkp::key::{PublicKey, SecretKey};
use secp256k1zkp::Secp256k1;
use serde::{Deserialize, Serialize};
use sha3::Keccak256;
use sled::Db;
use structopt::clap::{_clap_count_exprs, arg_enum};
use structopt::StructOpt;
use zeroize::Zeroize;

pub const NONCE_SIZE: usize = 8;

/// Struct for specifying secrets
#[derive(Serialize, Deserialize, Debug)]
pub struct Secrets {
    pub spend: SecretKey,
    pub view: SecretKey,
}

arg_enum! {
    /// Different address types
    #[derive(Debug)]
    pub enum AddressType {
        Spend,
        View,
    }
}

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
        #[structopt(
            name = "type",
            short,
            long,
            help = "Type of address",
            raw(
                possible_values = "&AddressType::variants()",
                case_insensitive = "true"
            )
        )]
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

    /// Returns public key derived from provided secret key
    pub fn get_public_key(secret_key: &SecretKey) -> Result<PublicKey, Error> {
        let secp = Secp256k1::new();
        Ok(PublicKey::from_secret_key(&secp, &secret_key)?)
    }

    /// Generates a random secret key
    fn generate_private_key() -> Result<SecretKey, Error> {
        let mut rand = OsRng::new()?;
        let secp = Secp256k1::new();

        Ok(SecretKey::new(&secp, &mut rand))
    }

    /// Generates random spend and view secret keys
    fn generate_secrets() -> Result<Secrets, Error> {
        let spend_secret_key = Self::generate_private_key()?;
        let view_secret_key = Self::generate_private_key()?;

        Ok(Secrets {
            spend: spend_secret_key,
            view: view_secret_key,
        })
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
            let secrets = Self::generate_secrets()?;

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

    /// Derives address from secret key
    fn get_address(secret_key: &SecretKey) -> Result<String, Error> {
        let public_key = Self::get_public_key(secret_key)?;

        let secp = Secp256k1::new();

        let mut hasher = Keccak256::new();
        hasher.input(&public_key.serialize_vec(&secp, false)[1..]);
        let hash = hasher.result()[12..].to_vec();

        Ok(encode(hash))
    }

    /// Retrieves address for a given name and type from storage
    fn get(
        name: &str,
        address_type: &Option<AddressType>,
        address_storage: &Db,
    ) -> Result<(), Error> {
        let secrets = Self::get_secrets(name, address_storage)?;

        if let Some(address_type) = address_type {
            use AddressType::*;

            match address_type {
                Spend => {
                    ask("Spend address: ");
                    success(&Self::get_address(&secrets.spend)?);
                }
                View => {
                    ask("View address: ");
                    success(&Self::get_address(&secrets.view)?);
                }
            }
        } else {
            ask("Spend address: ");
            success(&Self::get_address(&secrets.spend)?);

            ask("View address: ");
            success(&Self::get_address(&secrets.view)?);
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
