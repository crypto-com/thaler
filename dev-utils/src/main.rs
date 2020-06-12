mod commands;
mod dev_utils;
mod keypackage;

use structopt::StructOpt;

use client_common::Result;

use self::dev_utils::DevUtils;
pub use keypackage::{gen_keypackage, verify_keypackage};

fn main() {
    if let Err(err) = execute() {
        println!("Error: {:?}", err);
    }
}

fn execute() -> Result<()> {
    let dev_utils = DevUtils::from_args();
    dev_utils.execute()
}
