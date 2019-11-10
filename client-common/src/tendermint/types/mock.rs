#![allow(missing_docs)]
use super::*;
use serde_json;
use std::str::FromStr;
use tendermint::{
    account, block, chain, channel, net, node, validator, vote, Moniker, PrivateKey, PublicKey,
    Version,
};

static DEFAULT_VALIDATOR_KEY: &str = "{
  \"type\": \"tendermint/PrivKeyEd25519\",
  \"value\": \"gJWgIetdLxRc/C2t/XjV65NCqZLTqHS9pU69kBzRmyOKCHDqT/6bKPmKajdBp+KCbYtu9ttTX7+MXrEQOw8Kqg==\"
}";
static BLOCK_VERSION: u64 = 10;
static APP_VERSION: u64 = 0;
static APP_HASH: &str = "93E6C15E5A52CAAB971A810E5F6F9C4965AA102C81120FCEDCB7F8A112270380";

pub fn validator_priv_key() -> PrivateKey {
    serde_json::from_str(DEFAULT_VALIDATOR_KEY).unwrap()
}

pub fn validator_pub_key() -> PublicKey {
    validator_priv_key().public_key()
}

pub fn validator_account_id() -> account::Id {
    validator_pub_key().into()
}

pub fn default_chain_id() -> chain::Id {
    chain::Id::from_str("test-chain-ktDVXo-AB").unwrap()
}

pub fn validator_info() -> validator::Info {
    validator::Info {
        address: validator_account_id(),
        pub_key: validator_pub_key(),
        voting_power: vote::Power::new(12500000000),
        proposer_priority: None,
    }
}

pub fn node_info() -> node::Info {
    node::Info {
        protocol_version: node::info::ProtocolVersionInfo {
            p2p: 7,
            block: BLOCK_VERSION,
            app: APP_VERSION,
        },
        id: node::Id::from_str("7edc638f79308dfdfcd77b743e1375b8e1cea6f2").unwrap(),
        listen_addr: node::info::ListenAddress::new("tcp://0.0.0.0:26656".to_owned()),
        network: default_chain_id(),
        version: Version::default(),
        channels: channel::Channels::default(),
        moniker: Moniker::from_str("test").unwrap(),
        other: node::info::OtherInfo {
            tx_index: node::info::TxIndexStatus::On,
            rpc_address: net::Address::from_str("tcp://127.0.0.1:26657").unwrap(),
        },
    }
}

pub fn default_header() -> Header {
    Header {
        version: block::header::Version {
            block: BLOCK_VERSION,
            app: APP_VERSION,
        },
        chain_id: default_chain_id(),
        height: Height::default(),
        time: Time::default(),
        num_txs: 0,
        total_txs: 0,
        last_block_id: block::Id::default(),
        last_commit_hash: Hash::default(),
        data_hash: Hash::default(),
        validators_hash: Hash::default(),
        next_validators_hash: Hash::default(),
        consensus_hash: Hash::default(),
        app_hash: Hash::from_str(APP_HASH).unwrap(),
        last_results_hash: Hash::default(),
        evidence_hash: Hash::default(),
        proposer_address: validator_account_id(),
    }
}

pub fn default_block() -> Block {
    Block {
        header: default_header(),
        data: Default::default(),
        evidence: Default::default(),
        last_commit: block::Commit {
            block_id: Default::default(),
            precommits: Default::default(),
        },
    }
}

pub fn status_response() -> Status {
    Status {
        node_info: node_info(),
        sync_info: status::SyncInfo::default(),
        validator_info: validator_info(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn check_status_response() {
        println!("{}", serde_json::to_string(&status_response()).unwrap());
    }

    #[test]
    fn check_default_header() {
        println!("{}", serde_json::to_string(&default_header()).unwrap());
    }
}
