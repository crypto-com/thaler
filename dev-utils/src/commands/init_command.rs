use super::genesis_command::{GenesisCommand, GenesisDevConfig};
use chrono::offset::Utc;
use chrono::DateTime;
use chrono::{NaiveDateTime, TimeZone};
use failure::Error;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value as JsonValue;
use std::env;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process::Command;
use structopt::StructOpt;
#[derive(Debug, StructOpt)]
pub struct InitCommand {}

#[derive(Serialize, Deserialize)]
struct TendermintGenesis {
    pub app_hash: String,
    pub app_state: serde_json::Value,
    pub genesis_time: DateTime<Utc>,
}
impl TendermintGenesis {
    pub fn new() -> Self {
        TendermintGenesis {
            app_hash: "".to_string(),
            app_state: json!(null),
            genesis_time: Utc.timestamp(0, 0),
        }
    }
}

impl InitCommand {
    pub fn write(&self) {
        let data = r#"
        {
    "distribution": {
        "0x0db221c4f57d5d38b968139c06e9132aaf84e8df": "2500000000000000000",
        "0x20a0bee429d6907e556205ef9d48ab6fe6a55531": "2500000000000000000",
        "0x35f517cab9a37bc31091c2f155d965af84e0bc85": "2500000000000000000",
        "0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de": "1250000000000000000",
        "0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07": "1250000000000000000"
    },
    "unbonding_period": 60,
    "required_council_node_stake": "1250000000000000000",
    "initial_fee_policy": {
        "base_fee": "1.1",
        "per_byte_fee": "1.25"
    },
    "council_nodes": [
        {
            "staking_account_address": "0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de",
            "consensus_pubkey_type": "Ed25519",
            "consensus_pubkey_b64": "EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE="
        }
    ],
    "launch_incentive_from": "0x35f517cab9a37bc31091c2f155d965af84e0bc85",
    "launch_incentive_to": "0x20a0bee429d6907e556205ef9d48ab6fe6a55531",
    "long_term_incentive": "0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07",
    "genesis_time": "2019-03-21T02:26:51.366017Z"
}
        "#;
        let path = Path::new("./coin.json");
        let genesis_dev: GenesisDevConfig =
            serde_json::from_str(&data).expect("failed to parse genesis dev config");

        println!("{}", serde_json::to_string_pretty(&genesis_dev).unwrap());
        File::create(&path)
            .map(|mut file| {
                file.write_all(data.as_bytes()).unwrap();
                ()
            })
            .unwrap();

        println!("-----------------------------------------------");
        // app_hash,  app_state
        let result = GenesisCommand::generate(&path.to_path_buf()).unwrap();
        println!("genesis_time={}", genesis_dev.genesis_time);
        println!("-----------------------------------------------");
        self.write_tendermint_genesis(
            json!(result.0),
            serde_json::from_str(&result.1).unwrap(),
            json!(genesis_dev.genesis_time),
        );
    }
    pub fn write_tendermint_genesis(
        &self,
        app_hash: JsonValue,
        app_state: JsonValue,
        gt: JsonValue,
    ) -> Result<(), ()> {
        println!("write genesis");

        let filename = format!(
            "{}/.tendermint/config/genesis.json",
            env::home_dir().unwrap().to_str().unwrap()
        );
        // check whether file exists
        fs::read_to_string(filename.clone()).map_err(|_e| {
            // file not exist
            Command::new("tendermint").args(&["init"]).output();
            ();
            println!("tenermint initialized");
        });

        let mut json_string= String::from("");
        fs::read_to_string(filename.clone())
            .and_then(|contents| {
                let mut json: serde_json::Value = serde_json::from_str(&contents).unwrap();
                let obj = json.as_object_mut().unwrap();
                obj["app_hash"] = app_hash;
                obj.insert("app_state".to_string(), json!(""));
                obj["app_state"] = app_state;
                obj["genesis_time"] = gt;
                json_string = serde_json::to_string_pretty(&json).unwrap();
                println!("{}", json_string);
                
                File::create(&filename)
            })
            .map(|mut file| {
                file.write_all(json_string.as_bytes())
            })
            .map(|_e|  {
                println!("writing tendermint genesis OK");
                ()
            })
            .map_err(|e| {
                println!("Error={}", e);
                ()
            })
    }

    pub fn execute(&self) -> Result<(), Error> {
        println!("initialize");

        self.write();

        Ok(())
    }
}
