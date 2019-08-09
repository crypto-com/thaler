use failure::Error;
use structopt::StructOpt;

use crate::commands::GenesisCommand;
use crate::commands::InitCommand;
use crate::commands::RunCommand;
use crate::commands::StopCommand;

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
    #[structopt(
        name = "init",
        about = "Make a wallet, generate state, compute hash, and copies to tendermint's genesis.json"
    )]
    Init,

    /// Used for running
    #[structopt(name = "run", about = "run all chain components")]
    Run,

    /// Used for stopping
    #[structopt(name = "stop", about = "stop all chain components")]
    Stop,
}

impl DevUtils {
    pub fn execute(&self) -> Result<(), Error> {
        match self {
            DevUtils::Genesis { genesis_command } => genesis_command.execute(),
            DevUtils::Init => {
                let mut init_command = InitCommand::new();
                init_command.execute()
            }
            DevUtils::Run => {
                let mut run_command = RunCommand::new();
                run_command.execute()
            }
            DevUtils::Stop => {
                let mut stop_command = StopCommand::new();
                stop_command.execute()
            }
        }
    }
}
