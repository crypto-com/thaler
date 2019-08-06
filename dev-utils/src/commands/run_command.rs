use failure::{format_err, Error};
use std::process::Command;
#[derive(Debug)]
pub struct RunCommand {}

impl RunCommand {
    pub fn new() -> Self {
        RunCommand {}
    }

    pub fn run_program(&self, command: &str, arg: &[&str]) -> Result<(), Error> {
        Command::new(command)
            .args(arg)
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
        println!("run program");
        self.run_program("./tx-validation-app", "tcp://0.0.0.0:25933")
            .and_then(|_| {
                let args = vec![
                    "--host",
                    "0.0.0.0",
                    "--port",
                    "26658",
                    "--chain_id",
                    "test-ab",
                    "--genesis_app_hash",
                    "EE669DF9F2AED98FB980DD2DC1E42FFA329F8F84FCCD7C70B508B4994AD6FFA4",
                    "--enclave_server",
                    "tcp://127.0.0.1:25933",
                ];
                self.run_program("./chain-abci", args.as_slice())
            })
            .and_then(|_| self.run_program("./tendermint", vec!["node"].as_slice()))
    }
}
