use super::genesis_command::GenesisCommand;
use super::genesis_dev_config::GenesisDevConfig;
use chain_core::init::config::{InitialValidator, ValidatorKeyType};

use chain_core::init::{address::RedeemAddress, coin::Coin, config::InitConfig};
use chrono::DateTime;
use chrono::SecondsFormat;
use client_common::storage::SledStorage;
use client_core::wallet::{DefaultWalletClient, WalletClient};
use failure::ResultExt;
use failure::{format_err, Error};
use quest::{password, success};
use secstr::SecUtf8;
use serde_json::json;
use std::fs;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

use std::io::Write;

use client_common::ErrorKind;

#[derive(Debug)]
pub struct InitCommand {
    chainid: String,
    app_hash: String,
    app_state: Option<InitConfig>,
    genesis_dev: GenesisDevConfig,
    tendermint_pubkey: String,
    staking_account_address: String,
    distribution_addresses: Vec<String>,
    remain_coin: Coin,
}

impl InitCommand {
    pub fn new() -> Self {
        InitCommand {
            chainid: "".to_string(),
            app_hash: "".to_string(),
            app_state: None,
            genesis_dev: GenesisDevConfig::new(),
            tendermint_pubkey: "".to_string(),
            staking_account_address: "".to_string(),
            distribution_addresses: vec![],
            remain_coin: Coin::max(),
        }
    }

    /// easily add distribution wallet for development
    fn read_wallet(&mut self, id: &str, default_address: &str, default_amount: &str) {
        let address = self.ask_string(
            format!("wallet {}({}) address=", id, default_address).as_str(),
            default_address,
        );

        let amount = self.ask_string(
            format!("wallet {}({}) amount=", id, default_amount).as_str(),
            default_amount,
        );

        self.do_read_wallet(address, amount);
    }
    fn do_read_wallet(&mut self, address: String, amount_cro: String) {
        let amount_u64 = (amount_cro.parse::<f64>().unwrap() * 1_0000_0000_f64) as u64;
        let amount_coin = Coin::new(amount_u64).unwrap();

        let distribution = &mut self.genesis_dev.distribution;
        distribution.insert(RedeemAddress::from_str(&address).unwrap(), amount_coin);
        self.remain_coin = (self.remain_coin - amount_coin).unwrap();
        self.distribution_addresses.push(address.to_string());
    }
    fn check_chainid(&self, chainid: String) -> Result<(), Error> {
        if chainid.len() < 6 {
            return Err(format_err!("chainid too short"));
        }
        let networkid = &chainid[(chainid.len() - 2)..];
        let netkind = &chainid[..4];
        if "main" == netkind || "test" == netkind {
            // ok
        } else {
            return Err(format_err!("chain-id should start from main or test"));
        }

        hex::decode(networkid)
            .map(|_a| ())
            .map_err(|_a| format_err!("last two digits should be hex string such as AB"))
    }
    fn read_chainid(&mut self) -> Result<(), Error> {
        let chainid = self.ask_string(
            format!("new chain id( {} )=", self.chainid).as_str(),
            self.chainid.as_str(),
        );

        self.check_chainid(chainid.clone()).map(|_a| {
            self.chainid = chainid;
        })
    }
    fn read_wallets(&mut self) -> Result<(), Error> {
        let default_address = RedeemAddress::default().to_string();
        let default_addresses = [
            "0xc55139f8d416511020293dd3b121ee8beb3bd469",
            "0x9b4597438fc9e72617232a7aed37567405cb80dd",
            "0xf75dc04a0a77c8178a6880c44c6d8a8ffb436093",
        ];
        let default_coins = ["25000000000", "25000000000"];
        println!(
            "maximum coin to distribute={}",
            self.remain_coin.to_string()
        );

        assert!(42 == self.staking_account_address.len());
        self.do_read_wallet(
            self.staking_account_address.clone(),
            "12500000000".to_string(),
        );

        loop {
            let i = self.distribution_addresses.len();
            if self.remain_coin == Coin::zero() && i >= 4 {
                break;
            }
            let j = i - 1;
            let mut this_address = default_address.clone();
            let mut this_coin = self.remain_coin.to_string();
            if j < default_addresses.len() {
                this_address = default_addresses[j].to_string().clone();
            }
            if j < default_coins.len() {
                this_coin = default_coins[j].to_string().clone();
            }
            self.read_wallet(
                format!("{}", i).as_str(),
                this_address.as_str(),
                this_coin.as_str(),
            );
        }
        Ok(())
    }
    fn read_genesis_time(&mut self) -> Result<(), Error> {
        // change
        let old_genesis_time = self
            .genesis_dev
            .genesis_time
            .to_rfc3339_opts(SecondsFormat::Micros, true);

        let new_genesis_time: String = self.ask_string(
            format!("genesis_time( {} )=", old_genesis_time).as_str(),
            old_genesis_time.as_str(),
        );

        self.genesis_dev.genesis_time =
            DateTime::from(DateTime::parse_from_rfc3339(&new_genesis_time).unwrap());
        Ok(())
    }
    fn read_councils(&mut self) -> Result<(), Error> {
        let councils = &mut self.genesis_dev.council_nodes;
        println!(
            "{} {}",
            self.staking_account_address, self.tendermint_pubkey
        );
        let staking_validator = InitialValidator {
            staking_account_address: self
                .staking_account_address
                .parse::<RedeemAddress>()
                .unwrap(),
            consensus_pubkey_type: ValidatorKeyType::Ed25519,
            consensus_pubkey_b64: self.tendermint_pubkey.clone(),
        };

        councils.push(staking_validator);
        Ok(())
    }
    fn read_incentives(&mut self) -> Result<(), Error> {
        assert!(self.distribution_addresses.len() >= 4);

        self.genesis_dev.launch_incentive_from = RedeemAddress::from_str(&self.ask_string(
            format!("launch_incentive_from({})=", self.distribution_addresses[1]).as_str(),
            self.distribution_addresses[1].as_str(),
        ))
        .unwrap();
        self.genesis_dev.launch_incentive_to = RedeemAddress::from_str(&self.ask_string(
            format!("launch_incentive_to({})=", self.distribution_addresses[2]).as_str(),
            self.distribution_addresses[2].as_str(),
        ))
        .unwrap();
        self.genesis_dev.long_term_incentive = RedeemAddress::from_str(&self.ask_string(
            format!("long_term_incentive({})=", self.distribution_addresses[3]).as_str(),
            self.distribution_addresses[3].as_str(),
        ))
        .unwrap();
        Ok(())
    }
    // read information from user
    fn read_information(&mut self) -> Result<(), Error> {
        self.read_chainid()
            .and_then(|_| self.read_staking_address())
            .and_then(|_| self.read_wallets())
            .and_then(|_| self.read_genesis_time())
            .and_then(|_| self.read_councils())
            .and_then(|_| self.read_incentives())
    }
    fn generate_app_info(&mut self) -> Result<(), Error> {
        // app_hash,  app_state
        let result = GenesisCommand::do_generate(&self.genesis_dev).unwrap();
        self.app_hash = result.0;
        self.app_state = Some(result.1);
        Ok(())
    }
    pub fn get_tendermint_filename() -> String {
        match std::env::var("TENDERMINT_HOME") {
            Ok(path) => format!("{}/config/genesis.json", path).to_owned(),
            Err(_) => format!(
                "{}/.tendermint/config/genesis.json",
                dirs::home_dir().unwrap().to_str().unwrap()
            )
            .to_owned(),
        }
    }
    fn read_tendermint_genesis(&mut self) -> Result<(), Error> {
        // check whether file exists
        fs::read_to_string(&InitCommand::get_tendermint_filename())
            .and_then(|contents| {
                println!("current tendermint genesis={}", contents);
                let json: serde_json::Value = serde_json::from_str(&contents).unwrap();
                let pub_key = &json["validators"][0]["pub_key"]["value"];
                self.tendermint_pubkey = pub_key.as_str().unwrap().to_string();
                self.chainid = json["chain_id"].as_str().unwrap().to_string();
                Ok(())
            })
            .map_err(|_e| format_err!("read tendermint genesis error"))
    }
    fn write_tendermint_genesis(&self) -> Result<(), Error> {
        println!(
            "write genesis to {}",
            InitCommand::get_tendermint_filename()
        );

        let app_hash = self.app_hash.clone();
        let app_state = self.app_state.clone();
        let gt = self
            .genesis_dev
            .genesis_time
            .to_rfc3339_opts(SecondsFormat::Micros, true);
        let mut json_string = String::from("");
        fs::read_to_string(&InitCommand::get_tendermint_filename())
            .and_then(|contents| {
                let mut json: serde_json::Value = serde_json::from_str(&contents).unwrap();
                let obj = json.as_object_mut().unwrap();
                obj["app_hash"] = json!(app_hash);
                obj.insert("app_state".to_string(), json!(""));
                obj["app_state"] = json!(&app_state.unwrap());
                obj["genesis_time"] = json!(gt);
                obj["chain_id"] = json!(self.chainid.clone());
                json_string = serde_json::to_string(&json).unwrap();
                println!("{}", json_string);

                File::create(&InitCommand::get_tendermint_filename())
            })
            .map(|mut file| file.write_all(json_string.as_bytes()))
            .map(|_e| {
                println!(
                    "writing tendermint genesis OK {}",
                    InitCommand::get_tendermint_filename()
                );
            })
            .map_err(|_e| format_err!("write tendermint genesis error"))
    }

    fn prepare_tendermint(&self) -> Result<(), Error> {
        // check whether file exists
        fs::read_to_string(&InitCommand::get_tendermint_filename())
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

    fn reset_tendermint(&self) -> Result<(), Error> {
        // file not exist
        Command::new("tendermint")
            .args(&["unsafe_reset_all"])
            .output()
            .map(|_e| {
                println!("tenermint reset all");
                ()
            })
            .map_err(|_e| format_err!("tendermint not found"))
    }

    fn read_staking_address(&mut self) -> Result<(), Error> {
        let storage = SledStorage::new(InitCommand::storage_path())?;
        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()?;

        let name = self.ask_string("please enter wallet name=", "my");

        let passphrase = InitCommand::ask_passphrase()?;
        match wallet_client.new_wallet(&name.as_str(), &passphrase) {
            Ok(_a) => {}
            Err(b) => {
                println!("new wallet fail={}", b.to_string());
            }
        }
        success(&format!("Wallet created with name: {}", name));

        let address = wallet_client.new_staking_address(&name.as_str(), &passphrase)?;
        success(&format!("New address: {}", address));
        self.staking_account_address = address.to_string().trim().to_string();
        println!("staking address={}", self.staking_account_address);
        assert!(address.to_string().trim().to_string().len() == 42);
        Ok(())
    }

    fn clear_disk(&self) -> Result<(), Error> {
        let _ = fs::canonicalize(PathBuf::from("./.cro-storage")).and_then(|p| {
            let _ = fs::remove_dir_all(p);
            Ok(())
        });

        let _ = fs::canonicalize(PathBuf::from("./.storage")).and_then(|p| {
            let _ = fs::remove_dir_all(p);
            Ok(())
        });

        Ok(())
    }

    pub fn execute(&mut self) -> Result<(), Error> {
        println!("initialize chain");

        self.clear_disk()
            .and_then(|_| self.prepare_tendermint())
            .and_then(|_| self.reset_tendermint())
            .and_then(|_| self.read_tendermint_genesis())
            .and_then(|_| self.read_information())
            .and_then(|_| self.generate_app_info())
            .and_then(|_| self.write_tendermint_genesis())
            .map_err(|e| format_err!("init error={}", e))
    }

    fn storage_path() -> String {
        match std::env::var("CRYPTO_CLIENT_STORAGE") {
            Ok(path) => path,
            Err(_) => ".storage".to_owned(),
        }
    }

    fn ask_passphrase() -> client_common::Result<SecUtf8> {
        InitCommand::ask("Enter passphrase: ");
        Ok(password().context(ErrorKind::IoError)?.into())
    }

    /// Print a question, in bold, without creating a new line.
    fn ask(q: &str) {
        print!("\u{1B}[1m{}\u{1B}[0m", q);
        io::stdout().flush().unwrap();
    }

    fn ask_string(&self, msg: &str, default: &str) -> String {
        quest::ask(msg);
        match quest::text() {
            Ok(a) => {
                if "" == a {
                    default.to_string()
                } else {
                    a
                }
            }
            Err(_b) => default.to_string(),
        }
    }
}
