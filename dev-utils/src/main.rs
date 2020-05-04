mod commands;
mod dev_utils;

use structopt::StructOpt;

use client_common::Result;

use self::dev_utils::DevUtils;

fn main() {
    if let Err(err) = execute() {
        println!("Error: {:?}", err);
    }
}

fn execute() -> Result<()> {
    let dev_utils = DevUtils::from_args();
    dev_utils.execute()
}
