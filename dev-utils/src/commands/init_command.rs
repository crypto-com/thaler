use std::fs::{self, File};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

use quest::{password, success};
use secstr::SecUtf8;
use serde_json::json;

use chain_core::init::{address::RedeemAddress, coin::Coin, config::InitConfig};
use chain_core::state::{
    account::ConfidentialInit,
    tendermint::{TendermintValidator, TendermintValidatorPubKey},
};
use client_common::storage::SledStorage;
use client_common::tendermint::types::Time;
use client_common::{Error, ErrorKind, Result, ResultExt};
use client_core::types::WalletKind;
use client_core::wallet::{DefaultWalletClient, WalletClient};

use super::genesis_command::generate_genesis;
use super::genesis_dev_config::GenesisDevConfig;

#[derive(Debug)]
pub struct InitCommand {
    chain_id: String,
    app_hash: String,
    app_state: Option<InitConfig>,
    genesis_dev_config: GenesisDevConfig,
    tendermint_pubkey: String,
    staking_account_address: String,
    other_staking_accounts: Vec<String>,
    distribution_addresses: Vec<String>,
    remain_coin: Coin,
    tendermint_command: String,
    validators: Vec<TendermintValidator>,
    genesis_time: Time,
}

impl InitCommand {
    pub fn new() -> Self {
        let expansion_cap = Coin::new(2_500_000_000_000_000_000).unwrap();
        InitCommand {
            chain_id: "".to_string(),
            app_hash: "".to_string(),
            app_state: None,
            genesis_dev_config: GenesisDevConfig::new(expansion_cap),
            tendermint_pubkey: "".to_string(),
            staking_account_address: "".to_string(),
            other_staking_accounts: vec![],
            distribution_addresses: vec![],
            remain_coin: Coin::max(),
            tendermint_command: "./tendermint".to_string(),
            validators: Vec::new(),
            genesis_time: Time::unix_epoch(),
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

        let distribution = &mut self.genesis_dev_config.distribution;
        distribution.insert(RedeemAddress::from_str(&address).unwrap(), amount_coin);
        self.remain_coin = (self.remain_coin - amount_coin).unwrap();
        self.distribution_addresses.push(address);
    }

    fn check_chain_id(&self, chain_id: String) -> Result<()> {
        if chain_id.len() < 6 {
            return Err(Error::new(ErrorKind::InvalidInput, "Chain ID too small"));
        }

        let network_id = &chain_id[(chain_id.len() - 2)..];

        if !chain_id.starts_with("main")
            && !chain_id.starts_with("test")
            && !chain_id.starts_with("dev")
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Chain ID should start from main, test or dev",
            ));
        }

        hex::decode(network_id).map(|_| ()).chain(|| {
            (
                ErrorKind::InvalidInput,
                "Last two digits should be hex string such as AB",
            )
        })
    }

    fn read_chain_id(&mut self) -> Result<()> {
        let chain_id = self.ask_string(
            format!("new chain id( {} )=", self.chain_id).as_str(),
            self.chain_id.as_str(),
        );

        self.check_chain_id(chain_id.clone()).map(|_a| {
            self.chain_id = chain_id;
        })
    }

    fn read_wallets(&mut self) -> Result<()> {
        let default_address = RedeemAddress::default().to_string();
        assert!(self.other_staking_accounts.len() > 3);
        let default_addresses = self.other_staking_accounts.clone();
        let default_coins = [
            "12500000000",
            "12500000000",
            "12500000000",
            "12500000000",
            "12500000000",
        ];
        println!(
            "maximum coin to distribute = {}",
            self.remain_coin.to_string()
        );

        assert!(42 == self.staking_account_address.len());
        self.do_read_wallet(
            self.staking_account_address.clone(),
            "12500000000".to_string(),
        );

        loop {
            let i = self.distribution_addresses.len();
            if self.remain_coin
                == self
                    .genesis_dev_config
                    .rewards_config
                    .monetary_expansion_cap
            {
                break;
            }
            let j = i - 1;
            let mut this_address = default_address.clone();
            let mut this_coin = self.remain_coin.to_string();
            if j < default_addresses.len() {
                this_address = default_addresses[j].to_string();
            }
            if j < default_coins.len() {
                this_coin = default_coins[j].to_string();
            }
            self.read_wallet(
                format!("{}", i).as_str(),
                this_address.as_str(),
                this_coin.as_str(),
            );
        }
        Ok(())
    }

    fn read_councils(&mut self) -> Result<()> {
        println!(
            "{} {}",
            self.staking_account_address, self.tendermint_pubkey
        );
        let pubkey = TendermintValidatorPubKey::from_base64(self.tendermint_pubkey.as_bytes())
            .chain(|| {
                (
                    ErrorKind::InvalidInput,
                    "invalid base64 encoded validator public key",
                )
            })?;
        let address = self
            .staking_account_address
            .parse::<RedeemAddress>()
            .unwrap();
        self.genesis_dev_config.council_nodes.insert(
            address,
            (
                "dev test".to_owned(),
                None,
                pubkey,
                ConfidentialInit {
                    cert: b"FIXME".to_vec(),
                },
            ),
        );
        Ok(())
    }

    // read information from user
    fn read_information(&mut self) -> Result<()> {
        self.read_chain_id()
            .and_then(|_| self.read_staking_address())
            .and_then(|_| self.read_wallets())
            .and_then(|_| self.read_councils())
    }

    fn generate_app_info(&mut self) -> Result<()> {
        // app_hash,  app_state
        let result = generate_genesis(
            &self.genesis_dev_config,
            self.genesis_time
                .duration_since(Time::unix_epoch())
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        self.app_hash = result.0;
        self.app_state = Some(result.1);
        self.validators = result.2;
        Ok(())
    }

    pub fn get_tendermint_filename() -> String {
        match std::env::var("TENDERMINT_HOME") {
            Ok(path) => format!("{}/config/genesis.json", path),
            Err(_) => format!(
                "{}/.tendermint/config/genesis.json",
                dirs::home_dir().unwrap().to_str().unwrap()
            ),
        }
    }

    fn read_tendermint_genesis(&mut self) -> Result<()> {
        // check whether file exists
        fs::read_to_string(&InitCommand::get_tendermint_filename())
            .and_then(|contents| {
                println!("current tendermint genesis={}", contents);
                let json: serde_json::Value = serde_json::from_str(&contents).unwrap();
                let pub_key = &json["validators"][0]["pub_key"]["value"];
                self.tendermint_pubkey = pub_key.as_str().unwrap().to_string();
                self.chain_id = json["chain_id"].as_str().unwrap().to_string();
                self.genesis_time = Time::from_str(json["genesis_time"].as_str().unwrap()).unwrap();
                Ok(())
            })
            .chain(|| {
                (
                    ErrorKind::IoError,
                    "Unable to read tendermint initial config (genesis)",
                )
            })
    }

    fn write_overmind_procfile(&self) -> Result<()> {
        println!("write overmind Procfile");
        let mut a = "".to_string();
        a.push_str("enclave: ./tx-validation-app tcp://0.0.0.0:25933\n");
        a.push_str(format!("abci: ./chain-abci --host 0.0.0.0 --port 26658 --chain_id {}  --genesis_app_hash {}     --enclave_server tcp://127.0.0.1:25933 \n", self.chain_id,  self.app_hash).as_str());
        a.push_str("tendermint: ./tendermint node\n");

        File::create("./Procfile")
            .chain(|| (ErrorKind::IoError, "Procfile Create Fail"))
            .and_then(|mut file| {
                file.write_all(a.as_bytes())
                    .chain(|| (ErrorKind::IoError, "Procfile Write Fail"))
            })
    }
    fn write_tendermint_genesis(&self) -> Result<()> {
        println!(
            "write genesis to {}",
            InitCommand::get_tendermint_filename()
        );

        let app_hash = self.app_hash.clone();
        let app_state = self.app_state.clone();
        let gt = self.genesis_time.to_string();
        let mut json_string = String::from("");
        fs::read_to_string(&InitCommand::get_tendermint_filename())
            .and_then(|contents| {
                let mut json: serde_json::Value = serde_json::from_str(&contents).unwrap();
                let obj = json.as_object_mut().unwrap();
                obj["app_hash"] = json!(app_hash);
                obj.insert("app_state".to_string(), json!(""));
                obj["app_state"] = json!(&app_state.unwrap());
                obj["genesis_time"] = json!(gt);
                obj["chain_id"] = json!(self.chain_id.clone());
                obj["validators"] = json!(self.validators.clone());
                json_string = serde_json::to_string_pretty(&json).unwrap();
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
            .chain(|| (ErrorKind::IoError, "write tendermint genesis error"))
    }

    fn prepare_tendermint(&self) -> Result<()> {
        // check whether file exists
        fs::read_to_string(&InitCommand::get_tendermint_filename())
            .or_else(|_| {
                // file not exist
                Command::new(&self.tendermint_command)
                    .args(&["init"])
                    .output()
                    .map(|_| {
                        println!("tendermint initialized");
                        "".to_string()
                    })
                    .chain(|| (ErrorKind::IoError, "tendermint not found"))
            })
            .map(|_| ())
    }

    fn reset_tendermint(&self) -> Result<()> {
        // file not exist
        Command::new(&self.tendermint_command)
            .args(&["unsafe_reset_all"])
            .output()
            .map(|_| {
                println!("tendermint reset all");
            })
            .chain(|| (ErrorKind::IoError, "tendermint not found"))
    }

    fn read_staking_address(&mut self) -> Result<()> {
        let storage = SledStorage::new(InitCommand::storage_path())?;
        let wallet_client = DefaultWalletClient::new_read_only(storage);

        let name = self.ask_string("please enter wallet name=", "my");

        let passphrase = InitCommand::ask_passphrase()?;
        let enckey = match wallet_client.new_wallet(&name.as_str(), &passphrase, WalletKind::Basic)
        {
            Ok((enckey, _)) => enckey,
            Err(b) => {
                println!("new wallet fail={}", b.to_string());
                return Ok(());
            }
        };
        success(&format!("Wallet created with name: {}", name));

        // main validator staking
        let address = wallet_client.new_staking_address(&name.as_str(), &enckey)?;
        success(&format!("New address: {}", address));
        self.staking_account_address = address.to_string().trim().to_string();
        println!("staking address={}", self.staking_account_address);
        assert!(address.to_string().trim().to_string().len() == 42);

        for i in 0..6 {
            let address = wallet_client.new_staking_address(&name.as_str(), &enckey)?;
            self.other_staking_accounts
                .push(address.to_string().trim().to_string());
            success(&format!("Other New address {}: {}", i + 1, address));
        }

        Ok(())
    }

    fn clear_disk(&self) -> Result<()> {
        InitCommand::ask("** DANGER **\n");

        let first = self.ask_string(
            "will remove all storages including wallets and blocks please type cleardisk=",
            "",
        );
        let second = self.ask_string("please type cleardisk onemore=", "");
        if first == "cleardisk" && second == "cleardisk" {
            let _ = fs::canonicalize(PathBuf::from("./.cro-storage")).and_then(|p| {
                let _ = fs::remove_dir_all(p);
                Ok(())
            });

            let _ = fs::canonicalize(PathBuf::from("./.storage")).and_then(|p| {
                let _ = fs::remove_dir_all(p);
                Ok(())
            });

            Ok(())
        } else {
            Err(Error::new(ErrorKind::InvalidInput, "Unable to clear disk"))
        }
    }

    pub fn execute(&mut self) -> Result<()> {
        println!("initialize chain");

        let mut msg = "clear disk:".to_string();
        self.clear_disk()
            .and_then(|_| {
                msg.push_str("prepare tendermint:");
                self.prepare_tendermint()
            })
            .and_then(|_| {
                msg.push_str("reset tendermint:");
                self.reset_tendermint()
            })
            .and_then(|_| {
                msg.push_str("read tendermint genesis:");
                self.read_tendermint_genesis()
            })
            .and_then(|_| {
                msg.push_str("read information:");
                self.read_information()
            })
            .and_then(|_| {
                msg.push_str("generate app info:");
                self.generate_app_info()
            })
            .and_then(|_| {
                msg.push_str("write tendermint genesis:");
                self.write_tendermint_genesis()
            })
            .and_then(|_| {
                msg.push_str("write overmind procfile:");
                self.write_overmind_procfile()
            })
            .chain(|| {
                (
                    ErrorKind::InitializationError,
                    format!("Unable to initialize chain Steps=({})", msg),
                )
            })
    }

    fn storage_path() -> String {
        match std::env::var("CRYPTO_CLIENT_STORAGE") {
            Ok(path) => path,
            Err(_) => ".storage".to_owned(),
        }
    }

    fn ask_passphrase() -> Result<SecUtf8> {
        InitCommand::ask("Enter passphrase: ");
        Ok(password()
            .chain(|| (ErrorKind::IoError, "Unable to read password"))?
            .into())
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
