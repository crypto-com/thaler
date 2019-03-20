mod commands;
mod dev_utils;

use failure::Error;
use structopt::StructOpt;

use dev_utils::DevUtils;

fn main() {
    if let Err(err) = execute() {
        println!("Error: {}", err);
    }
}

fn execute() -> Result<(), Error> {
    let dev_utils = DevUtils::from_args();
    dev_utils.execute()
}
