use failure::Error;
use structopt::StructOpt;

use crate::commands::GenesisCommand;
use crate::commands::InitCommand;

/// Enum used to specify subcommands under dev-utils
#[derive(Debug, StructOpt)]
#[structopt(
    name = "dev-utils",
    about = "Basic CLI for development purposes (e.g. generation of genesis.json parameters)"
)]
pub enum DevUtils {
    /// Used for working with tendermint's genesis.json
    #[structopt(
        name = "genesis",
        about = "Commands for working with tendermint's genesis.json"
    )]
    Genesis {
        #[structopt(subcommand)]
        genesis_command: GenesisCommand,
    },

    /// Used for initializing
    #[structopt(name = "init", about = "Commands for initialize chain")]
    Init,
}

impl DevUtils {
    pub fn execute(&self) -> Result<(), Error> {
        match self {
            DevUtils::Genesis { genesis_command } => genesis_command.execute(),
            DevUtils::Init => {
                let mut init_command = InitCommand::new();
                init_command.execute().unwrap();
                Ok(())
            }
        }
    }
}
