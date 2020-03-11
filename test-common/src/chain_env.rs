use std::collections::BTreeMap;
use std::convert::TryInto;
use std::str::FromStr;
use std::sync::Arc;

use abci::*;
use kvdb_memorydb::create;
use protobuf::well_known_types::Timestamp;
use secp256k1::{
    key::{PublicKey, SecretKey},
    Message, Secp256k1, Signing,
};

use chain_abci::app::ChainNodeApp;
use chain_abci::enclave_bridge::mock::MockClient;
use chain_core::common::{MerkleTree, H256};
use chain_core::compute_app_hash;
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::init::config::{
    InitConfig, InitNetworkParameters, JailingParameters, NetworkParameters, RewardsParameters,
    SlashRatio, SlashingParameters,
};
use chain_core::state::account::{
    CouncilNode, StakedState, StakedStateAddress, StakedStateDestination, StakedStateOpAttributes,
    StakedStateOpWitness, UnbondTx, Validator as ChainValidator, ValidatorName,
    ValidatorSecurityContact,
};
use chain_core::state::tendermint::{
    TendermintValidatorAddress, TendermintValidatorPubKey, TendermintVotePower,
};
use chain_core::state::validator::NodeJoinRequestTx;
use chain_core::tx::fee::{LinearFee, Milli};
use chain_core::tx::witness::EcdsaSignature;
use chain_core::tx::{data::TxId, TransactionId, TxAux};
use chain_storage::account::{AccountStorage, AccountWrapper, StarlingFixedKey};
use chain_storage::buffer::Get;
use chain_storage::{Storage, NUM_COLUMNS};

const TEST_CHAIN_ID: &str = "test-00";

/// Need to add more seed and validator public keys, if need more validator nodes.
const SEEDS: [[u8; 32]; 2] = [[0xcd; 32], [0xab; 32]];
lazy_static! {
    static ref VALIDATOR_PUB_KEYS: Vec<TendermintValidatorPubKey> = [
        b"EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=",
        b"Vcrw/tEI0JOXw2SZGeowDxw5+Eot8qndCJoh2m6RC/M="
    ]
    .iter()
    .map(|s| TendermintValidatorPubKey::from_base64(*s).unwrap())
    .collect();
}

pub fn get_account(
    account_address: &StakedStateAddress,
    app: &ChainNodeApp<MockClient>,
) -> StakedState {
    app.staking_getter()
        .get(&account_address)
        .expect("account not found")
}

pub fn get_validator(
    account_address: &StakedStateAddress,
    app: &ChainNodeApp<MockClient>,
) -> ChainValidator {
    get_account(account_address, app).validator.unwrap()
}

pub fn get_ecdsa_witness<C: Signing>(
    secp: &Secp256k1<C>,
    txid: &TxId,
    secret_key: &SecretKey,
) -> EcdsaSignature {
    let message = Message::from_slice(&txid[..]).expect("32 bytes");
    secp.sign_recoverable(&message, &secret_key)
}

pub fn get_enclave_bridge_mock() -> MockClient {
    MockClient::new(0)
}

pub fn create_storage() -> (Storage, AccountStorage) {
    (
        Storage::new_db(Arc::new(create(NUM_COLUMNS))),
        AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20)
            .expect("Unable to create account storage"),
    )
}

pub fn get_init_network_params(expansion_cap: Coin) -> InitNetworkParameters {
    InitNetworkParameters {
        initial_fee_policy: LinearFee::new(Milli::new(0, 0), Milli::new(0, 0)),
        required_council_node_stake: Coin::unit(),
        unbonding_period: 61,
        jailing_config: JailingParameters {
            jail_duration: 60,
            block_signing_window: 5,
            missed_block_threshold: 1,
        },
        slashing_config: SlashingParameters {
            liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
            byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
            slash_wait_period: 5,
        },
        rewards_config: RewardsParameters {
            monetary_expansion_cap: expansion_cap,
            reward_period_seconds: 24 * 60 * 60, // distribute once per day
            monetary_expansion_r0: "0.5".parse().unwrap(),
            monetary_expansion_tau: 1_4500_0000_0000_0000,
            monetary_expansion_decay: 999_860,
        },
        max_validators: 50,
    }
}

pub fn get_nodes(
    addresses: &[Account],
) -> BTreeMap<
    RedeemAddress,
    (
        ValidatorName,
        ValidatorSecurityContact,
        TendermintValidatorPubKey,
    ),
> {
    addresses
        .iter()
        .map(|acct| {
            (
                acct.address,
                (acct.name.clone(), None, acct.validator_pub_key.clone()),
            )
        })
        .collect()
}

pub struct Account {
    pub secret_key: SecretKey,
    pub address: RedeemAddress,
    pub validator_pub_key: TendermintValidatorPubKey,
    pub name: String,
}

impl Account {
    pub fn new(
        seed: &[u8; 32],
        validator_pub_key: TendermintValidatorPubKey,
        name: String,
    ) -> Account {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(seed).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let address = RedeemAddress::from(&public_key);

        Account {
            secret_key,
            address,
            validator_pub_key,
            name,
        }
    }
    pub fn staking_address(&self) -> StakedStateAddress {
        StakedStateAddress::BasicRedeem(self.address)
    }
}

pub struct ChainEnv {
    pub dist_coin: Coin,
    pub expansion_cap: Coin,

    pub genesis_app_hash: H256,
    pub timestamp: Timestamp,
    pub init_config: InitConfig,
    pub council_nodes: Vec<(StakedStateAddress, CouncilNode)>,

    pub accounts: Vec<Account>,
}

impl ChainEnv {
    pub fn new(
        dist_coin: Coin,
        expansion_cap: Coin,
        count: usize,
    ) -> (ChainEnv, Storage, AccountStorage) {
        ChainEnv::new_with_customizer(dist_coin, expansion_cap, count, |_| {})
    }

    pub fn new_with_customizer<F: Fn(&mut InitNetworkParameters) -> ()>(
        dist_coin: Coin,
        expansion_cap: Coin,
        count: usize,
        customize_network_params: F,
    ) -> (ChainEnv, Storage, AccountStorage) {
        let (storage, mut account_storage) = create_storage();
        let locked = (Coin::max() - dist_coin - expansion_cap).unwrap();
        let accounts: Vec<Account> = (0..count)
            .map(|i| {
                Account::new(
                    &SEEDS[i],
                    VALIDATOR_PUB_KEYS[i].to_owned(),
                    format!("test {}", i),
                )
            })
            .collect();

        let share = (dist_coin / (accounts.len() as u64)).unwrap();
        let mut init_network_params = get_init_network_params(expansion_cap);
        customize_network_params(&mut init_network_params);

        let mut distribution = BTreeMap::new();
        if locked > Coin::zero() {
            distribution.insert(
                "0x0000000000000000000000000000000000000000"
                    .parse()
                    .unwrap(),
                (StakedStateDestination::UnbondedFromGenesis, locked),
            );
        }
        for acct in &accounts {
            distribution.insert(acct.address, (StakedStateDestination::Bonded, share));
        }

        let init_config = InitConfig::new(
            distribution,
            init_network_params.clone(),
            get_nodes(&accounts),
        );

        let timestamp = Timestamp::new();
        let (states, rewards_pool_state, council_nodes) = init_config
            .validate_config_get_genesis(timestamp.get_seconds().try_into().unwrap())
            .expect("Error while validating distribution");

        let mut keys: Vec<StarlingFixedKey> = states.iter().map(|account| account.key()).collect();
        let wrapped: Vec<AccountWrapper> =
            states.iter().map(|st| AccountWrapper(st.clone())).collect();

        let new_account_root = account_storage
            .insert(None, &mut keys, &wrapped)
            .expect("initial insert");

        let genesis_app_hash = compute_app_hash(
            &MerkleTree::empty(),
            &new_account_root,
            &rewards_pool_state,
            &NetworkParameters::Genesis(init_network_params),
        );
        (
            ChainEnv {
                dist_coin,
                expansion_cap,
                genesis_app_hash,
                timestamp,
                init_config,
                council_nodes,
                accounts,
            },
            storage,
            account_storage,
        )
    }

    pub fn share(&self) -> Coin {
        (self.dist_coin / (self.accounts.len() as u64)).unwrap()
    }

    pub fn chain_node(
        &self,
        storage: Storage,
        account_storage: AccountStorage,
    ) -> ChainNodeApp<MockClient> {
        ChainNodeApp::new_with_storage(
            get_enclave_bridge_mock(),
            &hex::encode_upper(self.genesis_app_hash),
            TEST_CHAIN_ID,
            storage,
            account_storage,
            None,
            None,
        )
    }

    pub fn join_tx(&self, nonce: u64, account_index: usize) -> TxAux {
        let tx = NodeJoinRequestTx::new(
            nonce,
            self.accounts[account_index].staking_address(),
            StakedStateOpAttributes::new(0),
            self.council_nodes[account_index].1.clone(),
        );
        let secp = Secp256k1::new();
        let witness = StakedStateOpWitness::new(get_ecdsa_witness(
            &secp,
            &tx.id(),
            &self.accounts[account_index].secret_key,
        ));
        TxAux::NodeJoinTx(tx, witness)
    }

    pub fn unbond_tx(&self, coin: Coin, nonce: u64, account_index: usize) -> TxAux {
        let tx = UnbondTx::new(
            self.accounts[account_index].staking_address(),
            nonce,
            coin,
            StakedStateOpAttributes::new(0),
        );
        let secp = Secp256k1::new();
        let witness = StakedStateOpWitness::new(get_ecdsa_witness(
            &secp,
            &tx.id(),
            &self.accounts[account_index].secret_key,
        ));
        TxAux::UnbondStakeTx(tx, witness)
    }

    pub fn req_init_chain(&self) -> RequestInitChain {
        let share = Coin::new(u64::from(self.dist_coin) / self.accounts.len() as u64).unwrap();
        let validators = self
            .accounts
            .iter()
            .map(|acct| ValidatorUpdate {
                pub_key: Some(PubKey {
                    field_type: "ed25519".to_owned(),
                    data: acct.validator_pub_key.as_bytes().to_vec(),
                    ..Default::default()
                })
                .into(),
                power: TendermintVotePower::from(share).into(),
                ..Default::default()
            })
            .collect();
        RequestInitChain {
            time: Some(self.timestamp.clone()).into(),
            app_state_bytes: serde_json::to_vec(&self.init_config).unwrap(),
            chain_id: TEST_CHAIN_ID.to_owned(),
            validators,
            ..Default::default()
        }
    }

    pub fn validator_address(&self, index: usize) -> TendermintValidatorAddress {
        self.council_nodes
            .iter()
            .find(|(address, _)| address == &self.accounts[index].staking_address())
            .expect("council node not found")
            .1
            .consensus_pubkey
            .clone()
            .into()
    }

    pub fn byzantine_evidence(&self, index: usize) -> Evidence {
        Evidence {
            validator: Some(Validator {
                address: <[u8; 20]>::from(&self.validator_address(index)).to_vec(),
                ..Default::default()
            })
            .into(),
            time: Some(::protobuf::well_known_types::Timestamp::default()).into(),
            ..Default::default()
        }
    }

    pub fn req_begin_block(&self, height: i64, proposed_by: usize) -> RequestBeginBlock {
        RequestBeginBlock {
            header: Some(Header {
                time: Some(Timestamp::new()).into(),
                chain_id: TEST_CHAIN_ID.to_owned(),
                height,
                proposer_address: Into::<[u8; 20]>::into(&self.validator_address(proposed_by))
                    .to_vec(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }

    pub fn req_begin_block_with_time(
        &self,
        height: i64,
        proposed_by: usize,
        time_sec: i64,
    ) -> RequestBeginBlock {
        RequestBeginBlock {
            header: Some(Header {
                time: Some(Timestamp {
                    seconds: time_sec,
                    ..Default::default()
                })
                .into(),
                chain_id: TEST_CHAIN_ID.to_owned(),
                height,
                proposer_address: Into::<[u8; 20]>::into(&self.validator_address(proposed_by))
                    .to_vec(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }

    pub fn last_commit_info(&self, index: usize, signed_last_block: bool) -> LastCommitInfo {
        LastCommitInfo {
            votes: self
                .accounts
                .iter()
                .enumerate()
                .map(|(i, _)| VoteInfo {
                    validator: Some(Validator {
                        address: <[u8; 20]>::from(&self.validator_address(i)).to_vec(),
                        ..Default::default()
                    })
                    .into(),
                    signed_last_block: if i == index { signed_last_block } else { true },
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    pub fn last_commit_info_signed(&self) -> LastCommitInfo {
        LastCommitInfo {
            votes: self
                .accounts
                .iter()
                .enumerate()
                .map(|(i, _)| VoteInfo {
                    validator: Some(Validator {
                        address: <[u8; 20]>::from(&self.validator_address(i)).to_vec(),
                        ..Default::default()
                    })
                    .into(),
                    signed_last_block: true,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }
}
