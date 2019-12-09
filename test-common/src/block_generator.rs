use std::collections::BTreeMap;
use std::str::FromStr;

use secstr::SecUtf8;
use serde_json;
use signatory::ed25519;
use signatory::public_key::PublicKeyed;
use signatory_dalek::Ed25519Signer;
use signature::Signer;
use subtle_encoding::{base64, hex};
use tendermint::amino_types::message::AminoMessage;
use tendermint::lite::{Header, ValidatorSet};
use tendermint::rpc::endpoint::status;
use tendermint::{
    account, amino_types, block, block::Height, chain, consensus, evidence, hash, node, public_key,
    rpc::endpoint::commit::SignedHeader, validator, vote, Block, Hash, PublicKey, Signature, Time,
};

use chain_abci::app::{compute_accounts_root, ChainNodeState, ValidatorState};
use chain_abci::storage::account::{pure_account_storage, AccountStorage};
use chain_abci::{liveness::LivenessTracker, punishment::ValidatorPunishment};
use chain_core::common::MerkleTree;
use chain_core::compute_app_hash;
use chain_core::init::config::NetworkParameters;
use chain_core::init::{
    address::RedeemAddress, coin::Coin, config::InitConfig, network::Network, params,
};
use chain_core::state::account::{CouncilNode, StakedStateAddress, StakedStateDestination};
use chain_core::state::tendermint::{
    TendermintValidatorAddress, TendermintValidatorPubKey, TendermintVotePower,
};
use chain_core::state::ChainState;
use chain_core::tx::fee::{LinearFee, Milli};
use chain_core::tx::TxAux;
use client_common::tendermint::types::{
    AbciQuery, BlockResults, BroadcastTxResponse, Genesis, Results,
};
use client_common::tendermint::{lite, Client};
use client_common::Result;
use client_core::{types::AddressType, HDSeed, Mnemonic};

lazy_static! {
    static ref DEFAULT_NODES: Vec<Node> = vec![Node::new(
        0,
        &b"zone fiber glory option pause arrive buyer stone match neutral obvious already deer equip depth".to_vec().into(),
        &hex::decode("c3f4422e8c21a6ebb03d45ce17a06c575f966a69aac1262900c08be4a5452ac4").unwrap(),
        &hex::decode("8bd612e59683b7c05a9dcd2e91ef277118327f1b93fb78ac3319bcd1587a1c0b").unwrap()
    )];
    static ref DEFAULT_CHAIN_ID: chain::Id = "test-chain-AB".parse().unwrap();
}

fn seed_to_pk(seed: &ed25519::Seed) -> ed25519::PublicKey {
    Ed25519Signer::from(seed).public_key().unwrap()
}

fn coin_to_power(coin: Coin) -> vote::Power {
    vote::Power::new(TendermintVotePower::from(coin).into())
}

#[derive(Clone)]
pub struct Node {
    pub index: u64,                    // validator index
    pub name: String,                  // name of the node
    pub wallet_seed: HDSeed,           // mnemonic for validator wallet
    pub validator_seed: ed25519::Seed, // seed to generate validator key pair
    pub p2p_seed: ed25519::Seed,       // seed to generate p2p network key pair
}

impl Node {
    pub fn new(
        index: u64,
        mnemonic_words: &SecUtf8,
        validator_bytes: &[u8],
        p2p_bytes: &[u8],
    ) -> Node {
        Node {
            index,
            name: format!("node{}", index),
            wallet_seed: HDSeed::from(
                &Mnemonic::from_secstr(mnemonic_words).expect("invalid mnemonic words"),
            ),
            validator_seed: ed25519::Seed::from_bytes(validator_bytes).unwrap(),
            p2p_seed: ed25519::Seed::from_bytes(p2p_bytes).unwrap(),
        }
    }

    pub fn council_node(&self) -> CouncilNode {
        CouncilNode {
            name: self.name.clone(),
            security_contact: Some(format!("{}@example.com", self.name)),
            consensus_pubkey: self.tendermint_pub_key(),
        }
    }

    pub fn validator_pub_key(&self) -> PublicKey {
        PublicKey::from_raw_ed25519(seed_to_pk(&self.validator_seed).as_bytes()).unwrap()
    }

    pub fn validator_pub_key_base64(&self) -> String {
        String::from_utf8(base64::encode(seed_to_pk(&self.validator_seed).as_bytes())).unwrap()
    }

    pub fn validator_address(&self) -> account::Id {
        account::Id::from(seed_to_pk(&self.validator_seed))
    }

    pub fn tendermint_pub_key(&self) -> TendermintValidatorPubKey {
        TendermintValidatorPubKey::Ed25519(seed_to_pk(&self.validator_seed).into_bytes())
    }

    pub fn tendermint_validator_address(&self) -> TendermintValidatorAddress {
        self.tendermint_pub_key().into()
    }

    pub fn node_id(&self) -> node::Id {
        node::Id::from(seed_to_pk(&self.p2p_seed))
    }

    pub fn redeem_address(&self, index: u32) -> RedeemAddress {
        let (vk, _sk) = self
            .wallet_seed
            .derive_key_pair(Network::Testnet, AddressType::Staking, index)
            .unwrap();
        RedeemAddress::from(&vk)
    }

    pub fn staking_address(&self, index: u32) -> StakedStateAddress {
        StakedStateAddress::from(self.redeem_address(index))
    }

    pub fn sign_msg(&self, msg: &[u8]) -> Signature {
        let signer = Ed25519Signer::from(&self.validator_seed);
        Signature::Ed25519(signer.try_sign(msg).expect("sign message failed"))
    }

    pub fn sign_header(&self, header: &block::Header, chain_id: &chain::Id) -> vote::Vote {
        let block_id = block::Id {
            hash: header.hash(),
            parts: None,
        };
        let now = Time::now();
        let canonical_vote = amino_types::vote::CanonicalVote {
            vote_type: vote::Type::Precommit.to_u32(),
            height: header.height.value() as i64,
            round: 0,
            block_id: Some(amino_types::block_id::CanonicalBlockId {
                hash: block_id.hash.as_bytes().to_vec(),
                parts_header: None,
            }),
            timestamp: Some(amino_types::time::TimeMsg::from(now)),
            chain_id: chain_id.to_string(),
        };
        let signature = self.sign_msg(&canonical_vote.bytes_vec_length_delimited());
        vote::Vote {
            vote_type: vote::Type::Precommit,
            height: header.height,
            round: 0,
            block_id: block_id.clone(),
            timestamp: now,
            validator_address: self.validator_address(),
            validator_index: self.index,
            signature,
        }
    }

    pub fn node_info(&self, chain_id: chain::Id) -> node::Info {
        node::Info {
            protocol_version: node::info::ProtocolVersionInfo {
                p2p: 7,
                block: 10,
                app: 0,
            },
            id: self.node_id(),
            listen_addr: node::info::ListenAddress::new("tcp://0.0.0.0:26656".to_owned()),
            network: chain_id,
            version: "0.32.7".parse().unwrap(),
            channels: serde_json::from_str("\"4020212223303800\"").unwrap(),
            moniker: self.name.parse().unwrap(),
            other: node::info::OtherInfo {
                tx_index: node::info::TxIndexStatus::On,
                rpc_address: "tcp://127.0.0.1:26667".parse().unwrap(),
            },
        }
    }

    pub fn validator_info(&self, share: Coin) -> validator::Info {
        validator::Info {
            address: self.validator_address(),
            pub_key: self.validator_pub_key(),
            voting_power: coin_to_power(share),
            proposer_priority: None,
        }
    }
}

pub struct TestnetSpec {
    pub nodes: Vec<Node>, // validator nodes.
    pub expansion_cap: Coin,
    pub base_fee: Milli,
    pub per_byte_fee: Milli,
    pub genesis_time: Time,
    pub chain_id: chain::Id,
}

impl TestnetSpec {
    pub fn new(nodes: Vec<Node>) -> TestnetSpec {
        TestnetSpec {
            nodes,
            expansion_cap: Coin::zero(),
            base_fee: "0.0".parse().unwrap(),
            per_byte_fee: "0.0".parse().unwrap(),
            genesis_time: Time::now(),
            chain_id: *DEFAULT_CHAIN_ID,
        }
    }

    pub fn share(&self) -> Coin {
        Coin::new(
            u64::from((Coin::max() - self.expansion_cap).unwrap()) / self.nodes.len() as u64 / 2,
        )
        .unwrap()
    }

    pub fn init_config(&self) -> InitConfig {
        let share = self.share();
        let mut distribution = BTreeMap::new();
        for node in &self.nodes {
            distribution.insert(
                node.redeem_address(0),
                (StakedStateDestination::Bonded, share),
            );
            distribution.insert(
                node.redeem_address(1),
                (StakedStateDestination::UnbondedFromGenesis, share),
            );
        }

        let mut council_nodes = BTreeMap::new();
        for node in &self.nodes {
            council_nodes.insert(
                node.redeem_address(0),
                (node.name.clone(), None, node.tendermint_pub_key()),
            );
        }

        InitConfig {
            distribution,
            network_params: gen_network_params(
                self.base_fee,
                self.per_byte_fee,
                self.expansion_cap,
            ),
            council_nodes,
        }
    }

    pub fn gen_genesis(&self) -> (Genesis, ChainNodeState, AccountStorage) {
        let account_storage = pure_account_storage(20).unwrap();

        let config = self.init_config();
        let genesis_seconds = self
            .genesis_time
            .duration_since(Time::unix_epoch())
            .expect("invalid genesis time")
            .as_secs();
        let (accounts, rewards_pool, _nodes) = config
            .validate_config_get_genesis(genesis_seconds)
            .expect("distribution validation error");
        let account_root = compute_accounts_root(&mut pure_account_storage(20).unwrap(), &accounts);
        let network_params = NetworkParameters::Genesis(config.network_params.clone());
        let app_hash = compute_app_hash(
            &MerkleTree::empty(),
            &compute_accounts_root(&mut pure_account_storage(20).unwrap(), &accounts),
            &rewards_pool,
            &network_params,
        );

        let share = self.share();
        let validators = self
            .nodes
            .iter()
            .map(|node| validator::Info {
                address: node.validator_address(),
                pub_key: node.validator_pub_key(),
                voting_power: vote::Power::new(TendermintVotePower::from(share).into()),
                proposer_priority: None,
            })
            .collect();

        let genesis = Genesis {
            genesis_time: self.genesis_time,
            chain_id: self.chain_id,
            consensus_params: consensus::Params {
                block: block::Size {
                    max_bytes: 22_020_096,
                    max_gas: -1,
                    time_iota_ms: 1000,
                },
                evidence: evidence::Params { max_age: 100_000 },
                validator: consensus::params::ValidatorParams {
                    pub_key_types: vec![public_key::Algorithm::Ed25519],
                },
            },
            validators,
            app_hash: Some(Hash::new(hash::Algorithm::Sha256, &app_hash).unwrap()),
            app_state: config,
        };

        let mut validator_liveness = BTreeMap::new();
        let mut validator_by_voting_power = BTreeMap::new();
        let mut tendermint_validator_addresses = BTreeMap::new();
        let power = TendermintVotePower::from(self.share());
        for node in self.nodes.iter() {
            let staking_address = node.staking_address(0);
            let validator_address = node.tendermint_validator_address();

            validator_by_voting_power.insert((power, staking_address), node.council_node());
            tendermint_validator_addresses.insert(validator_address.clone(), staking_address);
            validator_liveness.insert(
                validator_address.clone(),
                LivenessTracker::new(network_params.get_block_signing_window()),
            );
        }
        let validator_set = ValidatorState {
            council_nodes_by_power: validator_by_voting_power,
            tendermint_validator_addresses,
            punishment: ValidatorPunishment {
                validator_liveness,
                slashing_schedule: Default::default(),
            },
        };

        let state = ChainNodeState::genesis(
            app_hash,
            genesis_seconds,
            account_root,
            rewards_pool,
            network_params,
            validator_set,
        );

        (genesis, state, account_storage)
    }

    pub fn validator_set(&self) -> validator::Set {
        let share = self.share();
        validator::Set::new(
            self.nodes
                .iter()
                .map(|node| node.validator_info(share))
                .collect(),
        )
    }
}

pub struct BlockState {
    pub block: block::Block,
    pub commit: block::Commit,
    pub state: ChainNodeState,
}

impl BlockState {
    pub fn signed_header(&self) -> SignedHeader {
        SignedHeader {
            header: self.block.header.clone(),
            commit: self.commit.clone(),
        }
    }
}

pub struct BlockGenerator {
    pub spec: TestnetSpec,
    pub genesis: Genesis,
    pub genesis_state: ChainNodeState,
    pub account_storage: AccountStorage,
    pub validators: validator::Set,
    pub blocks: Vec<BlockState>,
    pub current_height: Option<Height>,
    pub node_index: usize,
}

impl BlockGenerator {
    pub fn new(spec: TestnetSpec) -> BlockGenerator {
        let (genesis, genesis_state, account_storage) = spec.gen_genesis();
        let validators = spec.validator_set();
        BlockGenerator {
            spec,
            genesis,
            genesis_state,
            account_storage,
            validators,
            blocks: vec![],
            current_height: None,
            node_index: 0,
        }
    }

    pub fn one_node() -> BlockGenerator {
        BlockGenerator::new(TestnetSpec::new(DEFAULT_NODES.clone()))
    }

    pub fn sync_info(&self) -> status::SyncInfo {
        if let Some(height) = self.current_height {
            let index = (height.value() - 1) as usize;
            status::SyncInfo {
                latest_block_hash: Some(self.blocks[index].block.header.hash()),
                latest_app_hash: self.genesis.app_hash,
                latest_block_height: height,
                latest_block_time: self.blocks[index].block.header.time,
                catching_up: false,
            }
        } else {
            status::SyncInfo {
                latest_block_hash: None,
                latest_app_hash: self.genesis.app_hash,
                latest_block_height: Height::default(),
                latest_block_time: Time::unix_epoch(),
                catching_up: false,
            }
        }
    }

    pub fn gen_block(&mut self, _txs: &[TxAux]) {
        let height = self
            .current_height
            .map_or(Height::default(), |height| height.increment());
        let last_block_id = self.blocks.last().map(|block| block::Id {
            hash: block.block.header.hash(),
            parts: None,
        });
        let last_state = self
            .blocks
            .last()
            .map_or(&self.genesis_state, |blk| &blk.state);
        let last_commit = self
            .current_height
            .map(|height| self.blocks[height.value() as usize - 1].commit.clone());

        let node = &self.spec.nodes[height.value() as usize % self.spec.nodes.len()];
        let consensus_hash =
            Hash::from_str("048091BC7DDC283F77BFBF91D73C44DA58C3DF8A9CBC867405D8B7F3DAADA22F")
                .unwrap(); // TODO real consensus hash
        let header = block::Header {
            version: block::header::Version { block: 10, app: 0 },
            chain_id: self.genesis.chain_id,
            height,
            time: Time::now(),
            num_txs: 0,
            total_txs: 0,
            last_block_id,
            last_commit_hash: None,
            data_hash: None,
            validators_hash: self.validators.hash(),
            next_validators_hash: self.validators.hash(),
            consensus_hash,
            app_hash: Some(Hash::new(hash::Algorithm::Sha256, &last_state.last_apphash).unwrap()),
            last_results_hash: None,
            evidence_hash: None,
            proposer_address: node.validator_address(),
        };
        let block_id = block::Id {
            hash: header.hash(),
            parts: None,
        };
        let votes: Vec<Option<vote::Vote>> = self
            .spec
            .nodes
            .iter()
            .map(|node| node.sign_header(&header, &self.genesis.chain_id))
            .map(Some)
            .collect();
        let commit = block::Commit {
            block_id,
            precommits: block::Precommits::new(votes),
        };
        let block = block::Block {
            header,
            data: Default::default(),
            evidence: Default::default(),
            last_commit,
        };

        let state = last_state.clone();
        self.blocks.push(BlockState {
            block,
            commit,
            state,
        })
    }

    pub fn signed_header(&self, height: Height) -> SignedHeader {
        self.blocks[(height.value() - 1) as usize].signed_header()
    }
}

impl Client for BlockGenerator {
    fn genesis(&self) -> Result<Genesis> {
        Ok(self.genesis.clone())
    }

    fn status(&self) -> Result<status::Response> {
        let node = &self.spec.nodes[self.node_index];
        Ok(status::Response {
            node_info: node.node_info(self.genesis.chain_id.clone()),
            sync_info: self.sync_info(),
            validator_info: node.validator_info(self.spec.share()),
        })
    }

    fn block(&self, height: u64) -> Result<Block> {
        Ok(self.blocks[height as usize - 1].block.clone())
    }

    fn block_batch<'a, T: Iterator<Item = &'a u64>>(&self, heights: T) -> Result<Vec<Block>> {
        heights.map(|height| self.block(*height)).collect()
    }

    fn block_results(&self, height: u64) -> Result<BlockResults> {
        Ok(BlockResults {
            height: Height::from(height),
            results: Results {
                deliver_tx: None,
                end_block: None,
            },
        })
    }

    fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
        &self,
        heights: T,
    ) -> Result<Vec<BlockResults>> {
        heights.map(|height| self.block_results(*height)).collect()
    }

    fn block_batch_verified<'a, T: Clone + Iterator<Item = &'a u64>>(
        &self,
        state: lite::TrustedState,
        heights: T,
    ) -> Result<(Vec<Block>, lite::TrustedState)> {
        Ok((self.block_batch(heights)?, state))
    }

    fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<BroadcastTxResponse> {
        unreachable!();
    }

    fn query(&self, _path: &str, _data: &[u8]) -> Result<AbciQuery> {
        unreachable!();
    }

    fn query_state_batch<T: Iterator<Item = u64>>(&self, heights: T) -> Result<Vec<ChainState>> {
        Ok(heights
            .map(|height| {
                if height == 0 {
                    self.genesis_state.top_level.clone()
                } else {
                    self.blocks[(height as usize).checked_sub(1).unwrap()]
                        .state
                        .top_level
                        .clone()
                }
            })
            .collect())
    }
}

fn gen_network_params(
    base_fee: Milli,
    per_byte_fee: Milli,
    expansion_cap: Coin,
) -> params::InitNetworkParameters {
    params::InitNetworkParameters {
        initial_fee_policy: LinearFee {
            constant: base_fee,
            coefficient: per_byte_fee,
        },
        required_council_node_stake: Coin::unit(),
        unbonding_period: 60,
        jailing_config: params::JailingParameters {
            jail_duration: 86400,
            block_signing_window: 100,
            missed_block_threshold: 50,
        },
        slashing_config: params::SlashingParameters {
            liveness_slash_percent: params::SlashRatio::from_str("0.1").unwrap(),
            byzantine_slash_percent: params::SlashRatio::from_str("0.2").unwrap(),
            slash_wait_period: 10800,
        },
        rewards_config: params::RewardsParameters {
            monetary_expansion_cap: expansion_cap,
            distribution_period: 24 * 60 * 60, // distribute once per day
            monetary_expansion_r0: "0.5".parse().unwrap(),
            monetary_expansion_tau: 166_666_600,
            monetary_expansion_decay: 999_860,
        },
        max_validators: 50,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tendermint::lite::verifier;

    #[test]
    fn check_lite_client() {
        let mut generator = BlockGenerator::one_node();
        generator.gen_block(&[]);
        generator.gen_block(&[]);

        generator.block(1).unwrap();
        generator.block(2).unwrap();

        let header1 = generator.signed_header(Height::default());
        let header2 = generator.signed_header(Height::default().increment());

        assert!(
            verifier::verify_trusting(
                header1.header.clone(),
                header1.clone(),
                generator.validators.clone(),
                generator.validators.clone(),
            )
            .is_ok(),
            "verify failed"
        );

        assert!(
            verifier::verify_trusting(
                header2.header.clone(),
                header2.clone(),
                generator.validators.clone(),
                generator.validators.clone(),
            )
            .is_ok(),
            "verify failed"
        );
    }
}
