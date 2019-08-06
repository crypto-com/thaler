use failure::{format_err, Error};

use std::process::Command;

#[derive(Debug)]
pub struct StopCommand {}

impl StopCommand {
    pub fn new() -> Self {
        StopCommand {}
    }

    pub fn run_program(&self, command: &str, arg: Vec<&str>) -> Result<(), Error> {
        Command::new(command)
            .args(arg.as_slice())
            .spawn()
            .map(|_e| {
                println!("{} launched!", command);
                ()
            })
            .map_err(|_e| {
                println!("{} error!", command);
                format_err!("{} launch error", command)
            })
            .and_then(|_e| {
                println!("{} run ok", command);
                Ok(())
            })
    }

    pub fn execute(&mut self) -> Result<(), Error> {
        println!("stop program");

        self.run_program(
            "killall",
            vec!["tx-validation-app", "tendermint", "chain-abci"],
        )
    }
}
