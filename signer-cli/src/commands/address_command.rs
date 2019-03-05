use failure::Error;
use quest::{ask, password, success};
use structopt::StructOpt;

use signer_core::{AddressType, Secrets, SecretsService};

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
    pub fn execute(&self, service: &SecretsService) -> Result<(), Error> {
        use AddressCommand::*;

        match self {
            Generate { name } => Self::generate(name, service),
            Get { name, address_type } => Self::get(name, address_type, service),
            List => Self::list(service),
            Clear => Self::clear(service),
        }
    }

    /// Clears address storage
    fn clear(service: &SecretsService) -> Result<(), Error> {
        service.clear()?;
        success("Cleared address storage");
        Ok(())
    }

    /// Returns the encryptor/decryptor for passphrase entered by user
    fn ask_passphrase() -> Result<String, Error> {
        ask("Enter passphrase: ");
        Ok(password()?)
    }

    /// Returns secrets for a given name
    pub fn get_secrets(name: &str, service: &SecretsService) -> Result<Secrets, Error> {
        let passphrase = Self::ask_passphrase()?;
        service.get(name, &passphrase)
    }

    /// Generates a secrets and stores them in storage after encryption
    fn generate(name: &str, service: &SecretsService) -> Result<(), Error> {
        let passphrase = Self::ask_passphrase()?;
        service.generate(name, &passphrase)?;

        success(&format!("Address generated for name: {}", name));
        Ok(())
    }

    /// Retrieves address for a given name and type from storage
    fn get(
        name: &str,
        address_type: &Option<AddressType>,
        service: &SecretsService,
    ) -> Result<(), Error> {
        use AddressType::*;

        let secrets = Self::get_secrets(name, service)?;

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
    fn list(service: &SecretsService) -> Result<(), Error> {
        let keys = service.list_keys()?;

        for key in keys {
            ask("Key name: ");
            success(&key);
        }

        Ok(())
    }
}
