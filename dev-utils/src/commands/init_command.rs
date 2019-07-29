use super::genesis_command::GenesisCommand;

use failure::Error;

use read_input::prelude::*;
use serde_json::json;
use serde_json::Value as JsonValue;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process::Command;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct InitCommand {
    data: String,
    genesis_time: JsonValue,
    app_hash: JsonValue,
    app_state: JsonValue,
    genesis_dev: JsonValue,
    tendermint_pubkey: String,
    staking_account_address: String,
    distribution_addresses: Vec<String>,
}

impl InitCommand {
    pub fn new() -> Self {
        InitCommand {
            genesis_time: json!(null),
            app_hash: json!(null),
            app_state: json!(null),
            genesis_dev: json!(null),
            tendermint_pubkey: "".to_string(),
            staking_account_address: "".to_string(),
            distribution_addresses: vec![],

            data: r#"
        {
    "distribution": {},
    "unbonding_period": 60,
    "required_council_node_stake": "1250000000000000000",
    "initial_fee_policy": {
        "base_fee": "1.1",
        "per_byte_fee": "1.25"
    },
    "council_nodes": [
       
    ],
    "launch_incentive_from": "0x35f517cab9a37bc31091c2f155d965af84e0bc85",
    "launch_incentive_to": "0x20a0bee429d6907e556205ef9d48ab6fe6a55531",
    "long_term_incentive": "0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07",
    "genesis_time": "2019-03-21T02:26:51.366017Z"
}
        "#
            .to_string(),
        }
    }

    pub fn read_wallet(&mut self, id: &str, default1: &str, default2: &str) {
        let obj = self.genesis_dev.as_object_mut().unwrap();
        let distribution = obj["distribution"].as_object_mut().unwrap();
        let a = input()
            .msg(format!("wallet {}({}) address=", id, default1))
            .default(default1.to_string())
            .get();
        let b = input()
            .msg(format!("wallet {}({}) amount=", id, default2))
            .default(default2.to_string())
            .get();
        distribution.insert(a.to_string(), json!(b));
        self.distribution_addresses.push(a.to_string());
    }
    pub fn read_information(&mut self) {
        println!("------------{}", self.tendermint_pubkey);
        self.genesis_dev =
            serde_json::from_str(&self.data).expect("failed to parse genesis dev config");

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
            let obj = self.genesis_dev.as_object_mut().unwrap();

            // change
            let old_genesis_time = obj["genesis_time"].as_str().unwrap().to_string();
            let new_genesis_time: String = input()
                .msg(format!("genesis_time( {} )=", old_genesis_time))
                .default(old_genesis_time)
                .get();
            obj["genesis_time"] = json!(new_genesis_time);
            // save
            self.genesis_time = obj["genesis_time"].clone();
            let councils = obj["council_nodes"].as_array_mut().unwrap();
            councils.push(json!({"consensus_pubkey_type": "Ed25519",}));

            councils[0]["staking_account_address"] = json!(self.staking_account_address);
            councils[0]["consensus_pubkey_b64"] = json!(self.tendermint_pubkey.as_str());

            obj["launch_incentive_from"] = json!(input()
                .msg(format!(
                    "launch_incentive_from({})=",
                    self.distribution_addresses[0]
                ))
                .default(self.distribution_addresses[0].clone())
                .get());
            obj["launch_incentive_to"] = json!(input()
                .msg(format!(
                    "launch_incentive_to({})=",
                    self.distribution_addresses[1]
                ))
                .default(self.distribution_addresses[1].clone())
                .get());
            obj["long_term_incentive"] = json!(input()
                .msg(format!(
                    "long_term_incentive({})=",
                    self.distribution_addresses[2]
                ))
                .default(self.distribution_addresses[2].clone())
                .get());
        }
        println!(
            "read_information={}",
            serde_json::to_string_pretty(&self.genesis_dev).unwrap()
        );
    }
    pub fn generate_app_info(&mut self) {
        let path = Path::new("./coin.json");

        println!(
            "{}",
            serde_json::to_string_pretty(&self.genesis_dev).unwrap()
        );
        File::create(&path)
            .map(|mut file| {
                let note = serde_json::to_string(&self.genesis_dev).unwrap();
                file.write_all(note.as_bytes()).unwrap();
                ()
            })
            .unwrap();

        println!("-----------------------------------------------");
        // app_hash,  app_state
        let result = GenesisCommand::generate(&path.to_path_buf()).unwrap();
        println!("genesis_time( {} )=", self.genesis_time);
        println!("-----------------------------------------------");
        self.app_hash = json!(result.0);
        self.app_state = serde_json::from_str(&result.1).unwrap();
    }
    pub fn get_tendermint_filename(&self) -> String {
        format!(
            "{}/.tendermint/config/genesis.json",
            dirs::home_dir().unwrap().to_str().unwrap()
        )
        .to_string()
    }
    pub fn read_tendermint_genesis(&mut self) {
        // check whether file exists
        let _dummy = fs::read_to_string(&self.get_tendermint_filename()).and_then(|contents| {
            println!("tendermint init!={}", contents);
            let json: serde_json::Value = serde_json::from_str(&contents).unwrap();
            let pub_key = &json["validators"][0]["pub_key"]["value"];
            self.tendermint_pubkey = pub_key.as_str().unwrap().to_string();
            Ok(())
        });
    }
    pub fn write_tendermint_genesis(&self) {
        println!("write genesis");

        let app_hash = self.app_hash.clone();
        let app_state = self.app_state.clone();
        let gt = self.genesis_time.clone();

        let mut json_string = String::from("");
        let _dummy = fs::read_to_string(&self.get_tendermint_filename())
            .and_then(|contents| {
                let mut json: serde_json::Value = serde_json::from_str(&contents).unwrap();
                let obj = json.as_object_mut().unwrap();
                obj["app_hash"] = app_hash;
                obj.insert("app_state".to_string(), json!(""));
                obj["app_state"] = app_state;
                obj["genesis_time"] = gt;
                json_string = serde_json::to_string_pretty(&json).unwrap();
                println!("{}", json_string);

                File::create(&self.get_tendermint_filename())
            })
            .map(|mut file| file.write_all(json_string.as_bytes()))
            .map(|_e| {
                println!("writing tendermint genesis OK");
            })
            .map_err(|e| {
                println!("Error={}", e);
            });
    }
    pub fn prepare_tendermint(&self) {
        // check whether file exists
        let _dummy = fs::read_to_string(&self.get_tendermint_filename()).map_err(|_e| {
            // file not exist
            Command::new("tendermint").args(&["init"]).output().unwrap();
            println!("tenermint initialized");
        });
    }
    pub fn execute(&mut self) -> Result<(), Error> {
        println!("initialize");

        self.prepare_tendermint();
        self.read_tendermint_genesis();
        self.read_information();
        self.generate_app_info();
        self.write_tendermint_genesis();

        Ok(())
    }
}
