use failure::Error;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct InitCommand {}

impl InitCommand {
    pub fn execute(&self) -> Result<(), Error> {
        println!("initialize");
        Ok(())
    }
}
