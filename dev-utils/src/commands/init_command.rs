use super::genesis_command::GenesisCommand;
use super::genesis_dev_config::GenesisDevConfig;
use chain_core::init::config::{InitialValidator, ValidatorKeyType};
use chain_core::init::{address::RedeemAddress, coin::Coin};
use chrono::DateTime;
use failure::{format_err, Error};
use read_input::prelude::*;
use serde_json::json;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::process::Command;
use std::str::FromStr;

#[derive(Debug)]
pub struct InitCommand {
    app_hash: String,
    app_state: String,
    genesis_dev: GenesisDevConfig,
    tendermint_pubkey: String,
    staking_account_address: String,
    distribution_addresses: Vec<String>,
}

impl InitCommand {
    pub fn new() -> Self {
        InitCommand {
            app_hash: "".to_string(),
            app_state: "".to_string(),
            genesis_dev: GenesisDevConfig::new(),
            tendermint_pubkey: "".to_string(),
            staking_account_address: "".to_string(),
            distribution_addresses: vec![],
        }
    }

    pub fn read_wallet(&mut self, id: &str, default1: &str, default2: &str) {
        let distribution = &mut self.genesis_dev.distribution;
        let a = input()
            .msg(format!("wallet {}({}) address=", id, default1))
            .default(default1.to_string())
            .get();
        let b = input()
            .msg(format!("wallet {}({}) amount=", id, default2))
            .default(default2.to_string())
            .get();
        distribution.insert(
            RedeemAddress::from_str(&a).unwrap(),
            Coin::from_str(&b).unwrap(),
        );
        self.distribution_addresses.push(a.to_string());
    }
    pub fn read_information(&mut self) -> Result<(), Error> {
        self.staking_account_address = input()
            .msg("Please staking_account_address(0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de)=")
            .default("0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de".to_string())
            .get();
        self.read_wallet(
            "1",
            "0x0db221c4f57d5d38b968139c06e9132aaf84e8df",
            "2500000000000000000",
        );
        self.read_wallet(
            "2",
            "0x20a0bee429d6907e556205ef9d48ab6fe6a55531",
            "2500000000000000000",
        );
        self.read_wallet(
            "3",
            "0x35f517cab9a37bc31091c2f155d965af84e0bc85",
            "2500000000000000000",
        );
        self.read_wallet(
            "4",
            self.staking_account_address.clone().as_str(),
            "1250000000000000000",
        );
        self.read_wallet(
            "5",
            "0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07",
            "1250000000000000000",
        );

        {
            // change
            let old_genesis_time = self.genesis_dev.genesis_time.to_rfc3339();
            let new_genesis_time: String = input()
                .msg(format!("genesis_time( {} )=", old_genesis_time))
                .default(old_genesis_time)
                .get();
            self.genesis_dev.genesis_time =
                DateTime::from(DateTime::parse_from_rfc3339(&new_genesis_time).unwrap());

            // save
            let councils = &mut self.genesis_dev.council_nodes;
            let staking_validator = InitialValidator {
                staking_account_address: self
                    .staking_account_address
                    .parse::<RedeemAddress>()
                    .unwrap(),
                consensus_pubkey_type: ValidatorKeyType::Ed25519,
                consensus_pubkey_b64: self.tendermint_pubkey.clone(),
            };

            councils.push(staking_validator);

            self.genesis_dev.launch_incentive_from = RedeemAddress::from_str(
                &input()
                    .msg(format!(
                        "launch_incentive_from({})=",
                        self.distribution_addresses[0]
                    ))
                    .default(self.distribution_addresses[0].clone())
                    .get(),
            )
            .unwrap();
            self.genesis_dev.launch_incentive_to = RedeemAddress::from_str(
                &input()
                    .msg(format!(
                        "launch_incentive_to({})=",
                        self.distribution_addresses[1]
                    ))
                    .default(self.distribution_addresses[1].clone())
                    .get(),
            )
            .unwrap();
            self.genesis_dev.long_term_incentive = RedeemAddress::from_str(
                &input()
                    .msg(format!(
                        "long_term_incentive({})=",
                        self.distribution_addresses[2]
                    ))
                    .default(self.distribution_addresses[2].clone())
                    .get(),
            )
            .unwrap();
        }

        Ok(())
    }
    pub fn generate_app_info(&mut self) -> Result<(), Error> {
        // app_hash,  app_state
        let result = GenesisCommand::do_generate(&self.genesis_dev).unwrap();
        self.app_hash = result.0;
        self.app_state = result.1;
        Ok(())
    }
    pub fn get_tendermint_filename(&self) -> String {
        format!(
            "{}/.tendermint/config/genesis.json",
            dirs::home_dir().unwrap().to_str().unwrap()
        )
        .to_string()
    }
    pub fn read_tendermint_genesis(&mut self) -> Result<(), Error> {
        // check whether file exists
        fs::read_to_string(&self.get_tendermint_filename())
            .and_then(|contents| {
                println!("current tendermint genesis={}", contents);
                let json: serde_json::Value = serde_json::from_str(&contents).unwrap();
                let pub_key = &json["validators"][0]["pub_key"]["value"];
                self.tendermint_pubkey = pub_key.as_str().unwrap().to_string();
                Ok(())
            })
            .map_err(|_e| format_err!("read tendermint genesis error"))
    }
    pub fn write_tendermint_genesis(&self) -> Result<(), Error> {
        println!("write genesis to {}", self.get_tendermint_filename());

        let app_hash = self.app_hash.clone();
        let app_state = self.app_state.clone();
        let gt = self.genesis_dev.genesis_time.to_rfc3339();

        let mut json_string = String::from("");
        fs::read_to_string(&self.get_tendermint_filename())
            .and_then(|contents| {
                let mut json: serde_json::Value = serde_json::from_str(&contents).unwrap();
                let obj = json.as_object_mut().unwrap();
                obj["app_hash"] = json!(app_hash);
                obj.insert("app_state".to_string(), json!(""));
                obj["app_state"] = json!(app_state);
                obj["genesis_time"] = json!(gt);
                json_string = serde_json::to_string_pretty(&json).unwrap();
                println!("{}", json_string);

                File::create(&self.get_tendermint_filename())
            })
            .map(|mut file| file.write_all(json_string.as_bytes()))
            .map(|_e| {
                println!(
                    "writing tendermint genesis OK {}",
                    self.get_tendermint_filename()
                );
            })
            .map_err(|_e| format_err!("write tendermint genesis error"))
    }
    pub fn prepare_tendermint(&self) -> Result<(), Error> {
        // check whether file exists
        fs::read_to_string(&self.get_tendermint_filename())
            .or_else(|_e| {
                // file not exist
                Command::new("tendermint")
                    .args(&["init"])
                    .output()
                    .map(|_e| {
                        println!("tenermint initialized");
                        "".to_string()
                    })
                    .map_err(|_e| format_err!("tendermint not found"))
            })
            .map(|_e| ())
    }
    pub fn execute(&mut self) -> Result<(), Error> {
        println!("initialize");

        self.prepare_tendermint()
            .and_then(|_| self.read_tendermint_genesis())
            .and_then(|_| self.read_information())
            .and_then(|_| self.generate_app_info())
            .and_then(|_| self.write_tendermint_genesis())
            .map_err(|e| format_err!("init error={}", e))
    }
}
