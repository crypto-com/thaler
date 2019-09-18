use std::process::Command;

use client_common::{ErrorKind, Result, ResultExt};

#[derive(Debug)]
pub struct StopCommand {}

impl StopCommand {
    pub fn new() -> Self {
        StopCommand {}
    }

    pub fn run_program(&self, command: &str, arg: Vec<&str>) -> Result<()> {
        Command::new(command)
            .args(arg.as_slice())
            .spawn()
            .map(|_| {
                println!("Command {} spawned", command);
            })
            .chain(|| {
                (
                    ErrorKind::IoError,
                    format!("Command {} failed to spawn", command),
                )
            })
    }

    pub fn execute(&mut self) -> Result<()> {
        println!("stop program");

        self.run_program(
            "killall",
            vec!["tx-validation-app", "tendermint", "chain-abci"],
        )
    }
}
