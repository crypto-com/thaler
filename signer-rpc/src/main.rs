mod address_rpc;
mod command;
mod transaction_rpc;

use command::Command;

use failure::Error;
use quest::error;
use structopt::StructOpt;

fn main() {
    if let Err(err) = execute() {
        error(&format!("Error: {}", err));
    }
}

fn execute() -> Result<(), Error> {
    let command = Command::from_args();
    command.execute()
}
