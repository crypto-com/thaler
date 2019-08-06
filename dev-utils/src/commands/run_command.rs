use failure::{format_err, Error};
use std::fs;
use std::process::Command;
use std::{thread, time};
#[derive(Debug)]
pub struct RunCommand {
    chainid: String,
    app_hash: String,
}

impl RunCommand {
    pub fn new() -> Self {
        RunCommand {
            chainid: "".to_string(),
            app_hash: "".to_string(),
        }
    }

    fn get_tendermint_filename(&self) -> String {
        format!(
            "{}/.tendermint/config/genesis.json",
            dirs::home_dir().unwrap().to_str().unwrap()
        )
        .to_string()
    }
    fn read_tendermint_genesis(&mut self) -> Result<(), Error> {
        // check whether file exists
        fs::read_to_string(&self.get_tendermint_filename())
            .and_then(|contents| {
                println!("current tendermint genesis={}", contents);
                let json: serde_json::Value = serde_json::from_str(&contents).unwrap();
                self.chainid = json["chain_id"].as_str().unwrap().to_string();
                self.app_hash = json["app_hash"].as_str().unwrap().to_string();
                println!("chainid={}", self.chainid);
                println!("app_hash={}", self.app_hash);
                Ok(())
            })
            .map_err(|_e| format_err!("read tendermint genesis error"))
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
        println!("run program");
        self.read_tendermint_genesis()
            .and_then(|_| {
                self.run_program(
                    "killall",
                    vec!["tx-validation-app", "tendermint", "chain-abci"],
                )
            })
            .and_then(|_| self.run_program("./tx-validation-app", vec!["tcp://0.0.0.0:25933"]))
            .and_then(|_| {
                let args = vec![
                    "--host",
                    "0.0.0.0",
                    "--port",
                    "26658",
                    "--chain_id",
                    self.chainid.as_str(),
                    "--genesis_app_hash",
                    self.app_hash.as_str(),
                    "--enclave_server",
                    "tcp://127.0.0.1:25933",
                ];
                self.run_program("./chain-abci", args)
            })
            .and_then(|_| {
                println!("wait for abci booting");
                thread::sleep(time::Duration::from_millis(3000));
                Ok(())
            })
            .and_then(|_| self.run_program("./tendermint", vec!["node"]))
    }
}
