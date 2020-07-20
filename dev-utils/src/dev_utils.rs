use structopt::StructOpt;

use client_common::Result;

use crate::commands::{
    GenesisCommand, InitCommand, KeypackageCommand, RunCommand, StopCommand, TestVectorCommand,
};

const NETWORKS: [&str; 3] = ["devnet", "testnet", "mainnet"];
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

    /// Create Test Vector
    #[structopt(name = "test-vectors", about = "create test vector")]
    TestVectors {
        #[structopt(
            name = "network",
            short,
            long,
            possible_values = &NETWORKS,
            case_insensitive = true,
            default_value = "mainnet",
            help = "network type",
        )]
        network: String,
        #[structopt(
            name = "seed",
            short,
            long,
            case_insensitive = true,
            default_value = "9ee5468093cf78ce008ace0b676b606d94548f8eac79e727e3cb0500ae739facca7bb5ee1f3dd698bc6fcd044117905d42d90fadf324c6187e1faba7e662410f",
            help = "hex format seed to generate private key"
        )]
        seed: String,
        #[structopt(
            name = "aux_payload",
            short,
            long,
            case_insensitive = true,
            default_value = "0000000000000000000000000000000000000000000000000000000000000000",
            help = "hex format aux payload used in schnorr_sign"
        )]
        aux_payload: String,
    },

    /// Used for working with tendermint's genesis.json
    #[structopt(name = "keypackage", about = "Commands for keypackage")]
    Keypackage {
        #[structopt(subcommand)]
        keypackage_command: KeypackageCommand,
    },
}

impl DevUtils {
    pub fn execute(&self) -> Result<()> {
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
            DevUtils::TestVectors {
                network,
                seed,
                aux_payload,
            } => {
                let test_vectors_command =
                    TestVectorCommand::new(network.clone(), seed.clone(), aux_payload);
                test_vectors_command.execute()
            }
            DevUtils::Keypackage { keypackage_command } => keypackage_command.execute(),
        }
    }
}
