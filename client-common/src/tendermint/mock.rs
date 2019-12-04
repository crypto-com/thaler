#![allow(missing_docs)]
use crate::tendermint::types::*;
use serde_json;
use std::str::FromStr;
use tendermint::{account, chain, channel, net, node, validator, Moniker, PrivateKey, PublicKey};

const DEFAULT_VALIDATOR_KEY: &str = "{
  \"type\": \"tendermint/PrivKeyEd25519\",
  \"value\": \"gJWgIetdLxRc/C2t/XjV65NCqZLTqHS9pU69kBzRmyOKCHDqT/6bKPmKajdBp+KCbYtu9ttTX7+MXrEQOw8Kqg==\"
}";
const BLOCK_VERSION: u64 = 10;
const APP_VERSION: u64 = 0;
const DEFAULT_GENESIS_JSON: &str = r#"{
    "genesis_time": "2019-11-18T05:49:16.254417Z",
    "chain_id": "test-chain-y3m1e6-AB",
    "consensus_params": {
        "block": {
            "max_bytes": "22020096",
            "max_gas": "-1",
            "time_iota_ms": "1000"
        },
        "evidence": {
            "max_age": "100000"
        },
        "validator": {
            "pub_key_types": [
                "ed25519"
            ]
        }
    },
    "validators": [
        {
            "address": "41D5FC236EDF35E68160BA0EA240A0E255EF6799",
            "pub_key": {
                "type": "tendermint/PubKeyEd25519",
                "value": "2H0sZxyy5iOU6q0/F+ZCQ3MyJJxg8odE5NMsGIyfFV0="
            },
            "power": "12500000000"
        }
    ],
    "app_hash": "92AA35815C976AE33FD6042DF445D032B4F0C761EEA24292E6CC73CC3EE18B72",
    "app_state": {
        "distribution": {
            "0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de": [
                "Bonded",
                "1250000000000000000"
            ],
            "0xbdf8b636b59b6dbec56eb07eb87d75dd0db3edd3": [
                "UnbondedFromGenesis",
                "2500000000000000000"
            ]
        },
        "network_params": {
            "initial_fee_policy": {
                "constant": 0,
                "coefficient": 0
            },
            "required_council_node_stake": "1250000000000000000",
            "unbonding_period": 15,
            "jailing_config": {
                "jail_duration": 86400,
                "block_signing_window": 100,
                "missed_block_threshold": 50
            },
            "slashing_config": {
                "liveness_slash_percent": "0.100",
                "byzantine_slash_percent": "0.200",
                "slash_wait_period": 10800
            },
            "rewards_config": {
                "monetary_expansion_cap": "6250000000000000000",
                "distribution_period": 86400,
                "monetary_expansion_r0": 500,
                "monetary_expansion_tau": 145000000,
                "monetary_expansion_decay": 999860
            },
            "max_validators": 50
        },
        "council_nodes": {
            "0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de": [
                "integration test",
                "security@integration.test",
                {
                    "consensus_pubkey_type": "Ed25519",
                    "consensus_pubkey_b64": "2H0sZxyy5iOU6q0/F+ZCQ3MyJJxg8odE5NMsGIyfFV0="
                }
            ]
        }
    }
}"#;

pub fn validator_priv_key() -> PrivateKey {
    serde_json::from_str(DEFAULT_VALIDATOR_KEY).unwrap()
}

pub fn validator_pub_key() -> PublicKey {
    validator_priv_key().public_key()
}

pub fn validator_account_id() -> account::Id {
    validator_pub_key().into()
}

pub fn commit_response() -> CommitResponse {
    serde_json::from_str(r#"{
    "signed_header": {
    "header": {
      "version": {
        "block": "10",
        "app": "0"
      },
      "chain_id": "test-chain-y3m1e6-AB",
      "height": "1",
      "time": "2019-11-18T05:49:16.254417Z",
      "num_txs": "0",
      "total_txs": "0",
      "last_block_id": {
        "hash": "",
        "parts": {
          "total": "0",
          "hash": ""
        }
      },
      "last_commit_hash": "",
      "data_hash": "",
      "validators_hash": "0138DDEDE3A25F8B89F63195C5D6D6C740A135458427529E17898A989063AC8E",
      "next_validators_hash": "0138DDEDE3A25F8B89F63195C5D6D6C740A135458427529E17898A989063AC8E",
      "consensus_hash": "048091BC7DDC283F77BFBF91D73C44DA58C3DF8A9CBC867405D8B7F3DAADA22F",
      "app_hash": "92AA35815C976AE33FD6042DF445D032B4F0C761EEA24292E6CC73CC3EE18B72",
      "last_results_hash": "",
      "evidence_hash": "",
      "proposer_address": "41D5FC236EDF35E68160BA0EA240A0E255EF6799"
    },
    "commit": {
      "block_id": {
        "hash": "E245B6E4B3FC65FF3A97EE7B6FC6135FDC004E9AACE54741B5E12C7FE10AAEC2",
        "parts": {
          "total": "1",
          "hash": "DEF22743C22E1B7D23F00540A1A7F2BBD0081CE796EFCFA1F952173524C14ADD"
        }
      },
      "precommits": [
        {
          "type": 2,
          "height": "1",
          "round": "0",
          "block_id": {
            "hash": "E245B6E4B3FC65FF3A97EE7B6FC6135FDC004E9AACE54741B5E12C7FE10AAEC2",
            "parts": {
              "total": "1",
              "hash": "DEF22743C22E1B7D23F00540A1A7F2BBD0081CE796EFCFA1F952173524C14ADD"
            }
          },
          "timestamp": "2019-11-18T05:49:27.794946Z",
          "validator_address": "41D5FC236EDF35E68160BA0EA240A0E255EF6799",
          "validator_index": "0",
          "signature": "PvYQ+yhwcN4oOTTJjdSVq75RzhXwelwWAtf3/8fNwNWlimRsNvk9NgIPWdwSirsSmM4J+IhKkkAVwFTkkBuPAg=="
        }
      ]
    }
  },
  "canonical": true
}"#).unwrap()
}

pub fn validators_response() -> ValidatorsResponse {
    serde_json::from_str(
        r#"{
  "block_height": "1",
  "validators": [
    {
      "address": "41D5FC236EDF35E68160BA0EA240A0E255EF6799",
      "pub_key": {
        "type": "tendermint/PubKeyEd25519",
        "value": "2H0sZxyy5iOU6q0/F+ZCQ3MyJJxg8odE5NMsGIyfFV0="
      },
      "voting_power": "12500000000",
      "proposer_priority": "0"
    }
  ]
}"#,
    )
    .unwrap()
}

pub fn chain_id() -> chain::Id {
    genesis().chain_id
}

pub fn validator_info() -> validator::Info {
    genesis().validators[0]
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
        network: chain_id(),
        version: "0.32.7".parse().unwrap(),
        channels: channel::Channels::default(),
        moniker: Moniker::from_str("test").unwrap(),
        other: node::info::OtherInfo {
            tx_index: node::info::TxIndexStatus::On,
            rpc_address: net::Address::from_str("tcp://127.0.0.1:26657").unwrap(),
        },
    }
}

pub fn genesis() -> Genesis {
    serde_json::from_str(DEFAULT_GENESIS_JSON).unwrap()
}

pub fn header() -> Header {
    block().header
}

pub fn block() -> Block {
    serde_json::from_str(
        r#"{
  "header": {
    "version": {
      "block": "10",
      "app": "0"
    },
    "chain_id": "test-chain-y3m1e6-AB",
    "height": "1",
    "time": "2019-11-18T05:49:16.254417Z",
    "num_txs": "0",
    "total_txs": "0",
    "last_block_id": {
      "hash": "",
      "parts": {
        "total": "0",
        "hash": ""
      }
    },
    "last_commit_hash": "",
    "data_hash": "",
    "validators_hash": "0138DDEDE3A25F8B89F63195C5D6D6C740A135458427529E17898A989063AC8E",
    "next_validators_hash": "0138DDEDE3A25F8B89F63195C5D6D6C740A135458427529E17898A989063AC8E",
    "consensus_hash": "048091BC7DDC283F77BFBF91D73C44DA58C3DF8A9CBC867405D8B7F3DAADA22F",
    "app_hash": "92AA35815C976AE33FD6042DF445D032B4F0C761EEA24292E6CC73CC3EE18B72",
    "last_results_hash": "",
    "evidence_hash": "",
    "proposer_address": "41D5FC236EDF35E68160BA0EA240A0E255EF6799"
  },
  "data": {
    "txs": null
  },
  "evidence": {
    "evidence": null
  },
  "last_commit": {
    "block_id": {
      "hash": "",
      "parts": {
        "total": "0",
        "hash": ""
      }
    },
    "precommits": null
  }
}"#,
    )
    .unwrap()
}

pub fn sync_info() -> status::SyncInfo {
    status::SyncInfo {
        latest_block_hash: None,
        latest_app_hash: None,
        latest_block_height: Height::default(),
        latest_block_time: Time::now(),
        catching_up: false,
    }
}

pub fn status_response() -> Status {
    Status {
        node_info: node_info(),
        sync_info: sync_info(),
        validator_info: validator_info(),
    }
}
