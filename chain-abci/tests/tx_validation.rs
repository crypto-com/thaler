use std::collections::HashMap;

use bit_vec::BitVec;
use chain_abci::app::staking_store;
/// FIXME: organize better / refactor (group by tx, less duplication or unneeded arguments)
use chain_abci::enclave_bridge::mock::MockClient;
use chain_abci::enclave_bridge::EnclaveProxy;
use chain_abci::staking_table::{NodeJoinError, StakingTable, UnbondError, UnjailError};
use chain_abci::storage::{
    process_public_tx, verify_enclave_tx as verify_enclave_tx_inner, TxEnclaveAction,
};
use chain_abci::tx::{PublicTxError, TxError};
use chain_core::common::{MerkleTree, Timespec};
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::{Coin, CoinError};
use chain_core::state::account::CouncilNode;
use chain_core::state::account::StakedState;
use chain_core::state::account::StakedStateAddress;
use chain_core::state::account::StakedStateOpAttributes;
use chain_core::state::account::{
    DepositBondTx, StakedStateOpWitness, UnbondTx, UnjailTx, Validator, WithdrawUnbondedTx,
};
use chain_core::state::tendermint::BlockHeight;
use chain_core::state::tendermint::TendermintValidatorPubKey;
use chain_core::state::validator::NodeJoinRequestTx;
use chain_core::tx::data::{
    address::ExtendedAddr,
    attribute::TxAttributes,
    input::{TxoIndex, TxoPointer},
    output::TxOut,
};
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::fee::FeeAlgorithm;
use chain_core::tx::fee::{Fee, LinearFee, Milli};
use chain_core::tx::witness::tree::RawXOnlyPubkey;
use chain_core::tx::witness::{TxInWitness, TxWitness};
use chain_core::tx::PlainTxAux;
use chain_core::tx::TransactionId;
use chain_core::tx::TxObfuscated;
use chain_core::tx::{TxAux, TxEnclaveAux};
use chain_storage::account::AccountStorage;
use chain_storage::account::AccountWrapper;
use chain_storage::account::StarlingFixedKey;
use chain_storage::buffer::{Get, StakingGetter};
use chain_storage::{Storage, COL_ENCLAVE_TX, COL_TX_META, NUM_COLUMNS};
use chain_tx_validation::{
    verify_bonded_deposit_core, verify_transfer, verify_unbonded_withdraw_core, ChainInfo, Error,
    TxWithOutputs,
};
use kvdb::KeyValueDB;
use kvdb_memorydb::create;
use parity_scale_codec::Encode;
use secp256k1::schnorrsig::schnorr_sign;
use secp256k1::{key::PublicKey, key::SecretKey, key::XOnlyPublicKey, Message, Secp256k1, Signing};
use std::fmt::Debug;
use std::mem;
use std::sync::Arc;

fn verify_enclave_tx<T: EnclaveProxy>(
    tx_validator: &mut T,
    txaux: &TxEnclaveAux,
    extra_info: ChainInfo,
    root: &StarlingFixedKey,
    storage: &Storage,
    accounts: &AccountStorage,
) -> Result<TxEnclaveAction, Error> {
    verify_enclave_tx_inner(
        tx_validator,
        storage,
        &StakingGetter::new(&accounts, Some(*root)),
        txaux,
        extra_info,
    )
}

fn verify_public_tx(
    txaux: &TxAux,
    extra_info: ChainInfo,
    info: NodeInfoWrap,
    root: &StarlingFixedKey,
    accounts: &AccountStorage,
) -> Result<(Fee, Option<StakedState>), TxError> {
    let mut tbl = StakingTable::from_genesis(
        &StakingGetter::new(&accounts, Some(*root)),
        info.0,
        50,
        &info.1,
    );
    let mut buffer = HashMap::new();
    let mut store = staking_store(&accounts, Some(*root), &mut buffer);
    let (fee, maddress) = process_public_tx(&mut store, &mut tbl, &extra_info, txaux)?;
    Ok((fee, maddress.map(|addr| store.get(&addr).unwrap())))
}

pub fn get_tx_witness<C: Signing>(
    secp: Secp256k1<C>,
    txid: &TxId,
    secret_key: &SecretKey,
    merkle_tree: &MerkleTree<RawXOnlyPubkey>,
) -> TxInWitness {
    let message = Message::from_slice(txid).unwrap();
    let public_key = XOnlyPublicKey::from_secret_key(&secp, secret_key);
    let proof = merkle_tree
        .generate_proof(RawXOnlyPubkey::from(public_key.serialize()))
        .unwrap();
    let signature = schnorr_sign(&secp, &message, secret_key);

    TxInWitness::TreeSig(signature, proof)
}

pub fn get_account_op_witness<C: Signing>(
    secp: Secp256k1<C>,
    txid: &TxId,
    secret_key: &SecretKey,
) -> StakedStateOpWitness {
    let message = Message::from_slice(&txid[..]).expect("32 bytes");
    let sig = secp.sign_recoverable(&message, &secret_key);
    return StakedStateOpWitness::new(sig);
}

fn create_db() -> Arc<dyn KeyValueDB> {
    Arc::new(create(NUM_COLUMNS))
}

fn create_storage() -> Storage {
    Storage::new_db(create_db())
}

fn get_enclave_bridge_mock() -> MockClient {
    MockClient::new(DEFAULT_CHAIN_ID)
}

fn get_old_tx(addr: ExtendedAddr, timelocked: bool) -> Tx {
    let mut old_tx = Tx::new();

    if timelocked {
        old_tx.add_output(TxOut::new_with_timelock(addr, Coin::one(), 20));
    } else {
        old_tx.add_output(TxOut::new_with_timelock(addr, Coin::one(), 0));
    }
    old_tx
}

fn get_address<C: Signing>(
    secp: &Secp256k1<C>,
    secret_key: &SecretKey,
) -> (ExtendedAddr, MerkleTree<RawXOnlyPubkey>) {
    let public_key = XOnlyPublicKey::from_secret_key(&secp, &secret_key);
    let merkle_tree = MerkleTree::new(vec![RawXOnlyPubkey::from(public_key.serialize())]);

    (ExtendedAddr::OrTree(merkle_tree.root_hash()), merkle_tree)
}

fn get_chain_info(txaux: &TxAux) -> ChainInfo {
    ChainInfo {
        min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
            .calculate_for_txaux(&txaux)
            .expect("invalid fee policy"),
        chain_hex_id: DEFAULT_CHAIN_ID,
        block_time: 0,
        unbonding_period: 1,
        block_height: BlockHeight::genesis(),
    }
}

fn get_chain_info_enc(txaux: &TxEnclaveAux) -> ChainInfo {
    get_chain_info(&TxAux::EnclaveTx(txaux.clone()))
}

struct NodeInfoWrap(
    Coin,                    // minimal_required_staking
    Vec<StakedStateAddress>, // genesis validators
);

impl Default for NodeInfoWrap {
    fn default() -> Self {
        Self(Coin::one(), Vec::new())
    }
}

impl NodeInfoWrap {
    pub fn custom(stake: Coin, validators: Vec<StakedStateAddress>) -> Self {
        NodeInfoWrap(stake, validators)
    }
}

fn prepate_init_tx(
    timelocked: bool,
) -> (
    Arc<dyn KeyValueDB>,
    TxoPointer,
    ExtendedAddr,
    MerkleTree<RawXOnlyPubkey>,
    SecretKey,
) {
    let db = create_db();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");

    let (addr, merkle_tree) = get_address(&secp, &secret_key);
    let old_tx = get_old_tx(addr.clone(), timelocked);

    let old_tx_id = old_tx.id();

    let mut inittx = db.transaction();
    // FIXME: https://github.com/crypto-com/chain/issues/885
    inittx.put(
        COL_ENCLAVE_TX,
        &old_tx_id[..],
        &TxWithOutputs::Transfer(old_tx).encode(),
    );

    inittx.put(
        COL_TX_META,
        &old_tx_id[..],
        &BitVec::from_elem(1, false).to_bytes(),
    );
    db.write(inittx).unwrap();
    let txp = TxoPointer::new(old_tx_id, 0);
    (db, txp, addr, merkle_tree, secret_key)
}

fn prepare_app_valid_transfer_tx(
    timelocked: bool,
) -> (
    Arc<dyn KeyValueDB>,
    TxEnclaveAux,
    Tx,
    TxWitness,
    MerkleTree<RawXOnlyPubkey>,
    SecretKey,
    AccountStorage,
) {
    let (db, txp, addr, merkle_tree, secret_key) = prepate_init_tx(timelocked);
    let secp = Secp256k1::new();
    let mut tx = Tx::new();
    tx.add_input(txp);
    tx.add_output(TxOut::new(addr, Coin::new(9).unwrap()));
    let sk2 = SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order");
    let addr2 = get_address(&secp, &sk2).0;
    tx.add_output(TxOut::new(addr2, Coin::new(1).unwrap()));

    let witness: Vec<TxInWitness> = vec![get_tx_witness(secp, &tx.id(), &secret_key, &merkle_tree)];
    let plain_txaux = PlainTxAux::new(tx.clone(), witness.clone().into());
    // TODO: mock enc
    let txaux = TxEnclaveAux::TransferTx {
        inputs: tx.inputs.clone(),
        no_of_outputs: tx.outputs.len() as TxoIndex,
        payload: TxObfuscated {
            txid: tx.id(),
            key_from: BlockHeight::genesis(),
            init_vector: [0; 12],
            txpayload: plain_txaux.encode(),
        },
    };
    (
        db,
        txaux,
        tx.clone(),
        witness.into(),
        merkle_tree,
        secret_key,
        AccountStorage::new(Storage::new_db(create_db()), 20).expect("account db"),
    )
}

fn prepare_app_valid_unbond_tx() -> (TxAux, UnbondTx, SecretKey, AccountStorage, StarlingFixedKey) {
    let mut tree = AccountStorage::new(Storage::new_db(create_db()), 20).expect("account db");
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let addr = RedeemAddress::from(&public_key);
    let account = StakedState::new(1, Coin::one(), Coin::zero(), 0, addr.into(), None);
    let key = account.key();
    let wrapped = AccountWrapper(account);
    let new_root = tree
        .insert(None, &mut [key], &mut vec![wrapped])
        .expect("insert");
    let tx = UnbondTx::new(
        addr.into(),
        1,
        Coin::new(9).unwrap(),
        StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
    );
    let witness = get_account_op_witness(secp, &tx.id(), &secret_key);
    let txaux = TxAux::UnbondStakeTx(tx.clone(), witness.clone());
    (txaux, tx.clone(), secret_key, tree, new_root)
}

#[test]
fn existing_account_unbond_tx_should_verify() {
    let (txaux, _, _, accounts, last_account_root_hash) = prepare_app_valid_unbond_tx();
    let extra_info = get_chain_info(&txaux);
    let result = verify_public_tx(
        &txaux,
        extra_info,
        NodeInfoWrap::default(),
        &last_account_root_hash,
        &accounts,
    );
    assert!(result.is_ok());
}

#[test]
fn test_account_unbond_verify_fail() {
    let (txaux, tx, secret_key, accounts, last_account_root_hash) = prepare_app_valid_unbond_tx();
    let extra_info = get_chain_info(&txaux);
    // WrongChainHexId
    {
        let mut extra_info = extra_info.clone();
        extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
        let result = verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &last_account_root_hash,
            &accounts,
        );
        expect_error_public(&result, PublicTxError::WrongChainHexId);
    }
    // UnsupportedVersion
    {
        let mut tx = tx.clone();
        tx.attributes.app_version = chain_core::APP_VERSION + 1;
        let txaux = TxAux::UnbondStakeTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &last_account_root_hash,
            &accounts,
        );
        expect_error_public(&result, PublicTxError::UnsupportedVersion);
    }
    // AccountNotFound, non exist account treated as a default account, so incorrect nonce.
    {
        let result = verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &[0; 32],
            &accounts,
        );
        expect_error_public(&result, PublicTxError::IncorrectNonce);
    }
    // AccountIncorrectNonce
    {
        let mut tx = tx.clone();
        tx.nonce = 0;
        let txaux = TxAux::UnbondStakeTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &last_account_root_hash,
            &accounts,
        );
        expect_error_public(&result, PublicTxError::IncorrectNonce);
    }
    // ZeroCoin
    {
        let mut tx = tx.clone();
        tx.value = Coin::zero();
        let txaux = TxAux::UnbondStakeTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &last_account_root_hash,
            &accounts,
        );
        expect_error_unbond(&result, UnbondError::ZeroValue);
    }
    // InputOutputDoNotMatch
    {
        let mut tx = tx.clone();
        tx.value = (tx.value + Coin::one()).unwrap();
        let txaux = TxAux::UnbondStakeTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &last_account_root_hash,
            &accounts,
        );
        expect_error_unbond(&result, UnbondError::CoinError(CoinError::Negative));
    }
}

fn prepare_app_valid_withdraw_tx(
    unbonded_from: Timespec,
) -> (
    TxEnclaveAux,
    WithdrawUnbondedTx,
    StakedStateOpWitness,
    StakedState,
    SecretKey,
    AccountStorage,
    StarlingFixedKey,
) {
    let mut tree = AccountStorage::new(Storage::new_db(create_db()), 20).expect("account db");
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let addr = RedeemAddress::from(&public_key);
    let account = StakedState::new(
        1,
        Coin::zero(),
        Coin::one(),
        unbonded_from,
        addr.into(),
        None,
    );
    let key = account.key();
    let wrapped = AccountWrapper(account.clone());
    let new_root = tree
        .insert(None, &mut [key], &mut vec![wrapped])
        .expect("insert");

    let sk2 = SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order");

    let addr1 = get_address(&secp, &secret_key).0;
    let addr2 = get_address(&secp, &sk2).0;

    let outputs = vec![
        TxOut::new_with_timelock(addr1, Coin::new(9).unwrap(), 0),
        TxOut::new_with_timelock(addr2, Coin::new(1).unwrap(), 0),
    ];

    let tx = WithdrawUnbondedTx::new(1, outputs, TxAttributes::new(DEFAULT_CHAIN_ID));
    let witness = get_account_op_witness(secp, &tx.id(), &secret_key);
    // TODO: mock enc
    let txaux = TxEnclaveAux::WithdrawUnbondedStakeTx {
        no_of_outputs: tx.outputs.len() as TxoIndex,
        witness: witness.clone(),
        payload: TxObfuscated {
            txid: tx.id(),
            key_from: BlockHeight::genesis(),
            init_vector: [0; 12],
            txpayload: PlainTxAux::WithdrawUnbondedStakeTx(tx.clone()).encode(),
        },
    };
    (
        txaux,
        tx.clone(),
        witness,
        account,
        secret_key,
        tree,
        new_root,
    )
}

#[test]
fn existing_account_withdraw_tx_should_verify() {
    let (txaux, _, _, _, _, accounts, last_account_root_hash) = prepare_app_valid_withdraw_tx(0);
    let extra_info = get_chain_info_enc(&txaux);
    let result = verify_enclave_tx(
        &mut get_enclave_bridge_mock(),
        &txaux,
        extra_info,
        &last_account_root_hash,
        &mut create_storage(),
        &accounts,
    );
    assert!(result.is_ok());
}

#[test]
fn test_account_withdraw_verify_fail() {
    let storage = create_storage();
    let (txaux, tx, _, account, secret_key, accounts, last_account_root_hash) =
        prepare_app_valid_withdraw_tx(0);
    let extra_info = get_chain_info_enc(&txaux);
    let mut mock_bridge = get_enclave_bridge_mock();
    // WrongChainHexId
    {
        let mut extra_info = extra_info.clone();
        extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, extra_info, &account);
        expect_error(&result, Error::WrongChainHexId);
    }
    // UnsupportedVersion
    {
        let mut tx = tx.clone();
        tx.attributes.app_version = chain_core::APP_VERSION + 1;
        let witness = get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::WithdrawUnbondedStakeTx(tx.clone()),
            Some(witness),
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, extra_info, &account);
        expect_error(&result, Error::UnsupportedVersion);
    }
    // NoOutputs
    {
        let mut tx = tx.clone();
        tx.outputs.clear();
        let witness = get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::WithdrawUnbondedStakeTx(tx.clone()),
            Some(witness),
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, extra_info, &account);
        expect_error(&result, Error::NoOutputs);
    }
    // ZeroCoin
    {
        let mut tx = tx.clone();
        tx.outputs[0].value = Coin::zero();
        let witness = get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::WithdrawUnbondedStakeTx(tx.clone()),
            Some(witness),
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, extra_info, &account);
        expect_error(&result, Error::ZeroCoin);
    }
    // InvalidSum
    {
        let mut tx = tx.clone();
        tx.outputs[0].value = Coin::max();
        let outp = tx.outputs[0].clone();
        tx.outputs.push(outp);
        let witness = get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::WithdrawUnbondedStakeTx(tx.clone()),
            Some(witness),
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, extra_info, &account);
        expect_error(
            &result,
            Error::InvalidSum, // FIXME: Error::InvalidSum(CoinError::OutOfBound(Coin::max().into())),
        );
    }
    // InputOutputDoNotMatch
    {
        let mut tx = tx.clone();
        tx.outputs[0].value = (tx.outputs[0].value + Coin::one()).unwrap();
        let witness = get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::WithdrawUnbondedStakeTx(tx.clone()),
            Some(witness),
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, extra_info, &account);
        expect_error(&result, Error::InputOutputDoNotMatch);
    }
    // AccountNotFound
    {
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &[0; 32],
            &storage,
            &accounts,
        );
        expect_error(&result, Error::AccountNotFound);
    }
    // AccountIncorrectNonce
    {
        let mut tx = tx.clone();
        tx.nonce = 0;
        let witness = get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::WithdrawUnbondedStakeTx(tx.clone()),
            Some(witness),
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, extra_info, &account);
        expect_error(&result, Error::AccountIncorrectNonce);
    }
    // AccountWithdrawOutputNotLocked
    {
        let mut tx = tx.clone();
        tx.outputs[0].valid_from = None;
        let witness = get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::WithdrawUnbondedStakeTx(tx.clone()),
            Some(witness),
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, extra_info, &account);
        expect_error(&result, Error::AccountWithdrawOutputNotLocked);
    }
    // AccountNotUnbonded
    {
        let (txaux, _, _, account, _, accounts, last_account_root_hash) =
            prepare_app_valid_withdraw_tx(20);
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, extra_info, &account);
        expect_error(&result, Error::AccountNotUnbonded);
    }
}

fn prepare_app_valid_deposit_tx(
    timelocked: bool,
) -> (
    Arc<dyn KeyValueDB>,
    TxEnclaveAux,
    DepositBondTx,
    TxWitness,
    SecretKey,
    AccountStorage,
) {
    let (db, txp, _, merkle_tree, secret_key) = prepate_init_tx(timelocked);
    let secp = Secp256k1::new();
    let sk2 = SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order");
    let pk2 = PublicKey::from_secret_key(&secp, &sk2);
    let tx = DepositBondTx::new(
        vec![txp],
        RedeemAddress::from(&pk2).into(),
        StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
    );

    let witness: Vec<TxInWitness> = vec![get_tx_witness(secp, &tx.id(), &secret_key, &merkle_tree)];
    // TODO: mock enc
    let txaux = TxEnclaveAux::DepositStakeTx {
        tx: tx.clone(),
        payload: TxObfuscated {
            txid: tx.id(),
            key_from: BlockHeight::genesis(),
            init_vector: [0u8; 12],
            txpayload: PlainTxAux::DepositStakeTx(witness.clone().into()).encode(),
        },
    };
    (
        db,
        txaux,
        tx.clone(),
        witness.into(),
        secret_key,
        AccountStorage::new(create_storage(), 20).expect("account db"),
    )
}

const DEFAULT_CHAIN_ID: u8 = 0;

#[test]
fn existing_utxo_input_tx_should_verify() {
    let mut mock_bridge = get_enclave_bridge_mock();
    let (db, txaux, _, _, _, _, accounts) = prepare_app_valid_transfer_tx(false);
    let storage = Storage::new_db(db);
    let extra_info = get_chain_info_enc(&txaux);
    let last_account_root_hash = [0u8; 32];
    let result = verify_enclave_tx(
        &mut mock_bridge,
        &txaux,
        extra_info,
        &last_account_root_hash,
        &storage,
        &accounts,
    );
    assert!(result.is_ok());
    let (db, txaux, _, _, _, accounts) = prepare_app_valid_deposit_tx(false);
    let storage = Storage::new_db(db);
    let result = verify_enclave_tx(
        &mut mock_bridge,
        &txaux,
        extra_info,
        &last_account_root_hash,
        &storage,
        &accounts,
    );
    assert!(result.is_ok());
}

fn expect_error<T, Error>(res: &Result<T, Error>, expected: Error)
where
    Error: Debug,
{
    match res {
        Err(err) if mem::discriminant(&expected) == mem::discriminant(err) => {}
        Err(err) => panic!("Expected error {:?} but got {:?}", expected, err),
        Ok(_) => panic!("Expected error {:?} but succeeded", expected),
    }
}

fn expect_error_public<T>(res: &Result<T, TxError>, expected: PublicTxError) {
    match res {
        Err(TxError::Public(err)) if mem::discriminant(&expected) == mem::discriminant(err) => {}
        Err(err) => panic!("Expected error {:?} but got {:?}", expected, err),
        Ok(_) => panic!("Expected error {:?} but succeeded", expected),
    }
}

fn expect_error_unbond<T>(res: &Result<T, TxError>, expected: UnbondError) {
    match res {
        Err(TxError::Public(PublicTxError::Unbond(err)))
            if mem::discriminant(&expected) == mem::discriminant(err) => {}
        Err(err) => panic!("Expected error {:?} but got {:?}", expected, err),
        Ok(_) => panic!("Expected error {:?} but succeeded", expected),
    }
}

fn expect_error_joinnode<T>(res: &Result<T, TxError>, expected: NodeJoinError) {
    match res {
        Err(TxError::Public(PublicTxError::NodeJoin(err)))
            if mem::discriminant(&expected) == mem::discriminant(err) => {}
        Err(err) => panic!("Expected error {:?} but got {:?}", expected, err),
        Ok(_) => panic!("Expected error {:?} but succeeded", expected),
    }
}

fn expect_error_unjail<T>(res: &Result<T, TxError>, expected: UnjailError) {
    match res {
        Err(TxError::Public(PublicTxError::Unjail(err)))
            if mem::discriminant(&expected) == mem::discriminant(err) => {}
        Err(err) => panic!("Expected error {:?} but got {:?}", expected, err),
        Ok(_) => panic!("Expected error {:?} but succeeded", expected),
    }
}

#[test]
fn test_deposit_verify_fail() {
    let mut mock_bridge = get_enclave_bridge_mock();
    let (db, txaux, tx, witness, secret_key, accounts) = prepare_app_valid_deposit_tx(false);
    let storage = Storage::new_db(db.clone());
    let extra_info = get_chain_info_enc(&txaux);
    let last_account_root_hash = [0u8; 32];
    // WrongChainHexId
    {
        let mut extra_info = extra_info.clone();
        extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &witness, extra_info, vec![]);
        expect_error(&result, Error::WrongChainHexId);
    }
    // UnsupportedVersion
    {
        let mut tx = tx.clone();
        tx.attributes.app_version = chain_core::APP_VERSION + 1;
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::DepositStakeTx(witness.clone()),
            None,
            Some(tx.clone()),
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &witness, extra_info, vec![]);
        expect_error(&result, Error::UnsupportedVersion);
    }
    // NoInputs
    {
        let mut tx = tx.clone();
        tx.inputs.clear();
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::DepositStakeTx(witness.clone()),
            None,
            Some(tx.clone()),
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &witness, extra_info, vec![]);
        expect_error(&result, Error::NoInputs);
    }
    // DuplicateInputs
    {
        let mut tx = tx.clone();
        let inp = tx.inputs[0].clone();
        tx.inputs.push(inp);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::DepositStakeTx(witness.clone()),
            None,
            Some(tx.clone()),
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &witness, extra_info, vec![]);
        expect_error(&result, Error::DuplicateInputs);
    }
    // UnexpectedWitnesses
    {
        let mut witness = witness.clone();
        let wp = witness[0].clone();
        witness.push(wp);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::DepositStakeTx(witness.clone()),
            None,
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &witness, extra_info, vec![]);
        expect_error(&result, Error::UnexpectedWitnesses);
    }
    // MissingWitnesses
    {
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::DepositStakeTx(vec![].into()),
            None,
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &vec![].into(), extra_info, vec![]);
        expect_error(&result, Error::MissingWitnesses);
    }
    // InputSpent
    {
        let mut inittx = db.transaction();
        inittx.put(
            COL_TX_META,
            &tx.inputs[0].id[..],
            &BitVec::from_elem(1, true).to_bytes(),
        );
        db.write(inittx).unwrap();

        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        expect_error(&result, Error::InputSpent);

        let mut reset = db.transaction();
        reset.put(
            COL_TX_META,
            &tx.inputs[0].id[..],
            &BitVec::from_elem(1, false).to_bytes(),
        );
        db.write(reset).unwrap();
    }
    // Invalid signature (EcdsaCrypto)
    {
        let secp = Secp256k1::new();
        let mut witness = witness.clone();
        witness[0] = get_tx_witness(
            secp.clone(),
            &tx.id(),
            &SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order"),
            &MerkleTree::new(vec![RawXOnlyPubkey::from(
                XOnlyPublicKey::from_secret_key(
                    &secp,
                    &SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order"),
                )
                .serialize(),
            )]),
        );
        let addr = get_address(&secp, &secret_key).0;
        let input_tx = get_old_tx(addr, false);

        let result = verify_bonded_deposit_core(
            &tx,
            &witness,
            extra_info,
            vec![TxWithOutputs::Transfer(input_tx)],
        );
        expect_error(
            &result,
            Error::EcdsaCrypto, // FIXME: Error::EcdsaCrypto(secp256k1::Error::InvalidPublicKey),
        );
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::DepositStakeTx(witness.clone()),
            None,
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
    }
    // InvalidInput
    {
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &mut create_storage(),
            &accounts,
        );
        expect_error(&result, Error::InvalidInput);
    }
    // InputOutputDoNotMatch
    {
        let mut extra_info = extra_info.clone();
        extra_info.min_fee_computed = Fee::new(Coin::one());
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &witness, extra_info, vec![]);
        expect_error(&result, Error::InputOutputDoNotMatch);
    }
}

fn replace_tx_payload(
    txaux: TxEnclaveAux,
    plain_tx: PlainTxAux,
    mwitness: Option<StakedStateOpWitness>,
    mtx: Option<DepositBondTx>,
) -> TxEnclaveAux {
    match (txaux, plain_tx.clone()) {
        (
            TxEnclaveAux::TransferTx {
                payload:
                    TxObfuscated {
                        key_from,
                        init_vector,
                        ..
                    },
                ..
            },
            PlainTxAux::TransferTx(tx, _),
        ) => TxEnclaveAux::TransferTx {
            inputs: tx.inputs.clone(),
            no_of_outputs: tx.outputs.len() as TxoIndex,
            payload: TxObfuscated {
                txid: tx.id(),
                key_from,
                init_vector,
                txpayload: plain_tx.encode(),
            },
        },
        (
            TxEnclaveAux::DepositStakeTx {
                tx,
                payload:
                    TxObfuscated {
                        key_from,
                        init_vector,
                        ..
                    },
            },
            PlainTxAux::DepositStakeTx(_),
        ) => TxEnclaveAux::DepositStakeTx {
            tx: if let Some(t) = mtx { t } else { tx.clone() },
            payload: TxObfuscated {
                txid: tx.id(),
                key_from,
                init_vector,
                txpayload: plain_tx.encode(),
            },
        },
        (
            TxEnclaveAux::WithdrawUnbondedStakeTx {
                witness,
                payload:
                    TxObfuscated {
                        key_from,
                        init_vector,
                        ..
                    },
                ..
            },
            PlainTxAux::WithdrawUnbondedStakeTx(tx),
        ) => TxEnclaveAux::WithdrawUnbondedStakeTx {
            no_of_outputs: tx.outputs.len() as TxoIndex,
            witness: if let Some(w) = mwitness { w } else { witness },
            payload: TxObfuscated {
                txid: tx.id(),
                key_from,
                init_vector,
                txpayload: plain_tx.encode(),
            },
        },
        _ => unreachable!(),
    }
}

#[test]
fn test_transfer_verify_fail() {
    let mut mock_bridge = get_enclave_bridge_mock();
    let (db, txaux, tx, witness, merkle_tree, secret_key, accounts) =
        prepare_app_valid_transfer_tx(false);
    let storage = Storage::new_db(db.clone());
    let extra_info = get_chain_info_enc(&txaux);
    let last_account_root_hash = [0u8; 32];
    // WrongChainHexId
    {
        let mut extra_info = extra_info.clone();
        extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_transfer(&tx, &witness, extra_info, vec![]);
        expect_error(&result, Error::WrongChainHexId);
    }
    // UnsupportedVersion
    {
        let mut tx = tx.clone();
        tx.attributes.app_version = chain_core::APP_VERSION + 1;
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx, witness.clone()),
            None,
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        expect_error(&result, Error::UnsupportedVersion);
    }
    // NoInputs
    {
        let mut tx = tx.clone();
        tx.inputs.clear();
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx, witness.clone()),
            None,
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        expect_error(&result, Error::NoInputs);
    }
    // NoOutputs
    {
        let mut tx = tx.clone();
        tx.outputs.clear();
        let result = verify_transfer(&tx, &witness, extra_info, vec![]);
        expect_error(&result, Error::NoOutputs);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx, witness.clone()),
            None,
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
    }
    // DuplicateInputs
    {
        let mut tx = tx.clone();
        let inp = tx.inputs[0].clone();
        tx.inputs.push(inp);
        let result = verify_transfer(&tx, &witness, extra_info, vec![]);
        expect_error(&result, Error::DuplicateInputs);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx, witness.clone()),
            None,
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
    }
    // ZeroCoin
    {
        let mut tx = tx.clone();
        tx.outputs[0].value = Coin::zero();
        let result = verify_transfer(&tx, &witness, extra_info, vec![]);
        expect_error(&result, Error::ZeroCoin);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx, witness.clone()),
            None,
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
    }
    // UnexpectedWitnesses
    {
        let mut witness = witness.clone();
        let wp = witness[0].clone();
        witness.push(wp);
        let result = verify_transfer(&tx, &witness, extra_info, vec![]);
        expect_error(&result, Error::UnexpectedWitnesses);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx.clone(), witness),
            None,
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
    }
    // MissingWitnesses
    {
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx.clone(), vec![].into()),
            None,
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
        let result = verify_transfer(&tx.clone(), &vec![].into(), extra_info, vec![]);
        expect_error(&result, Error::MissingWitnesses);
    }
    // InvalidSum
    {
        let mut tx = tx.clone();
        tx.outputs[0].value = Coin::max();
        let outp = tx.outputs[0].clone();
        tx.outputs.push(outp);
        let mut witness = witness.clone();
        witness[0] = get_tx_witness(Secp256k1::new(), &tx.id(), &secret_key, &merkle_tree);
        let result = verify_transfer(&tx, &witness, extra_info, vec![]);
        expect_error(
            &result,
            Error::InvalidSum, // FIXME: Error::InvalidSum(CoinError::OutOfBound(Coin::max().into())),
        );
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx, witness),
            None,
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
    }
    // InputSpent
    {
        let mut inittx = db.transaction();
        inittx.put(
            COL_TX_META,
            &tx.inputs[0].id[..],
            &BitVec::from_elem(1, true).to_bytes(),
        );
        db.write(inittx).unwrap();

        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        expect_error(&result, Error::InputSpent);

        let mut reset = db.transaction();
        reset.put(
            COL_TX_META,
            &tx.inputs[0].id[..],
            &BitVec::from_elem(1, false).to_bytes(),
        );
        db.write(reset).unwrap();
    }
    // Invalid signature (EcdsaCrypto)
    {
        let secp = Secp256k1::new();
        let mut witness = witness.clone();
        witness[0] = get_tx_witness(
            secp.clone(),
            &tx.id(),
            &SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order"),
            &MerkleTree::new(vec![RawXOnlyPubkey::from(
                XOnlyPublicKey::from_secret_key(
                    &secp,
                    &SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order"),
                )
                .serialize(),
            )]),
        );
        let addr = get_address(&secp, &secret_key).0;
        let input_tx = get_old_tx(addr, false);

        let result = verify_transfer(
            &tx,
            &witness,
            extra_info,
            vec![TxWithOutputs::Transfer(input_tx)],
        );
        expect_error(
            &result,
            Error::EcdsaCrypto, // FIXME: Error::EcdsaCrypto(secp256k1::Error::InvalidPublicKey),
        );
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx.clone(), witness),
            None,
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
    }
    // InvalidInput
    {
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &mut create_storage(),
            &accounts,
        );
        expect_error(&result, Error::InvalidInput);
    }
    // InputOutputDoNotMatch
    {
        let mut tx = tx.clone();
        let mut witness = witness.clone();

        tx.outputs[0].value = (tx.outputs[0].value + Coin::one()).unwrap();
        witness[0] = get_tx_witness(Secp256k1::new(), &tx.id(), &secret_key, &merkle_tree);
        let result = verify_transfer(&tx, &witness, extra_info, vec![]);
        expect_error(&result, Error::InputOutputDoNotMatch);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx, witness),
            None,
            None,
        );
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
    }
    // OutputInTimelock
    {
        let (db, txaux, tx, witness, _, _, accounts) = prepare_app_valid_transfer_tx(true);
        let storage = Storage::new_db(db);
        let addr = get_address(&Secp256k1::new(), &secret_key).0;
        let input_tx = get_old_tx(addr, true);
        let result = verify_transfer(
            &tx,
            &witness,
            extra_info,
            vec![TxWithOutputs::Transfer(input_tx)],
        );
        expect_error(&result, Error::OutputInTimelock);
        let result = verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            &storage,
            &accounts,
        );
        assert!(result.is_err());
    }
}

fn prepare_jailed_accounts() -> (
    Arc<dyn KeyValueDB>,
    AccountStorage,
    SecretKey,
    RedeemAddress,
    MerkleTree<RawXOnlyPubkey>,
    StarlingFixedKey,
) {
    let db = create_db();
    let mut accounts = AccountStorage::new(Storage::new_db(db.clone()), 20).expect("account db");

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let x_public_key = XOnlyPublicKey::from_secret_key(&secp, &secret_key);
    let merkle_tree = MerkleTree::new(vec![RawXOnlyPubkey::from(x_public_key.serialize())]);

    let addr = RedeemAddress::from(&public_key);
    let account = StakedState::new(
        1,
        Coin::one(),
        Coin::one(),
        0,
        addr.into(),
        Some(Validator {
            council_node: CouncilNode::new(TendermintValidatorPubKey::Ed25519([0xcd; 32])),
            jailed_until: Some(100),
            inactive_time: Some(0),
            inactive_block: Some(BlockHeight::genesis()),
            used_validator_addresses: vec![],
        }),
    );

    let key = account.key();
    let wrapped = AccountWrapper(account.clone());
    let root = accounts
        .insert(None, &mut [key], &mut vec![wrapped])
        .expect("insert");

    (db, accounts, secret_key, addr, merkle_tree, root)
}

fn prepare_withdraw_transaction(secret_key: &SecretKey) -> TxEnclaveAux {
    let secp = Secp256k1::new();

    let tx = WithdrawUnbondedTx::new(1, vec![], TxAttributes::new(DEFAULT_CHAIN_ID));
    let witness = get_account_op_witness(secp, &tx.id(), secret_key);

    TxEnclaveAux::WithdrawUnbondedStakeTx {
        no_of_outputs: tx.outputs.len() as TxoIndex,
        witness: witness.clone(),
        payload: TxObfuscated {
            txid: tx.id(),
            key_from: BlockHeight::genesis(),
            init_vector: [0; 12],
            txpayload: PlainTxAux::WithdrawUnbondedStakeTx(tx.clone()).encode(),
        },
    }
}

fn prepare_deposit_transaction(
    secret_key: &SecretKey,
    address: RedeemAddress,
    merkle_tree: &MerkleTree<RawXOnlyPubkey>,
) -> TxEnclaveAux {
    let secp = Secp256k1::new();

    let tx = DepositBondTx::new(
        vec![],
        address.into(),
        StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
    );

    let witness: Vec<TxInWitness> = vec![get_tx_witness(secp, &tx.id(), secret_key, merkle_tree)];

    TxEnclaveAux::DepositStakeTx {
        tx: tx.clone(),
        payload: TxObfuscated {
            txid: tx.id(),
            key_from: BlockHeight::genesis(),
            init_vector: [0u8; 12],
            txpayload: PlainTxAux::DepositStakeTx(witness.into()).encode(),
        },
    }
}

fn prepare_unbond_transaction(secret_key: &SecretKey, address: StakedStateAddress) -> TxAux {
    let secp = Secp256k1::new();

    let tx = UnbondTx::new(
        address,
        1,
        Coin::new(9).unwrap(),
        StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
    );
    let witness = get_account_op_witness(secp, &tx.id(), &secret_key);

    TxAux::UnbondStakeTx(tx, witness)
}

fn prepare_unjail_transaction(
    secret_key: &SecretKey,
    address: StakedStateAddress,
    nonce: u64,
) -> TxAux {
    let secp = Secp256k1::new();

    let tx = UnjailTx {
        nonce,
        address,
        attributes: StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
    };
    let witness = get_account_op_witness(secp, &tx.id(), &secret_key);

    TxAux::UnjailTx(tx, witness)
}

#[test]
fn check_verify_fail_for_jailed_account() {
    let mut mock_bridge = get_enclave_bridge_mock();
    let (db, accounts, secret_key, address, merkle_tree, root) = prepare_jailed_accounts();
    let storage = Storage::new_db(db);
    // Withdraw transaction

    let txaux = prepare_withdraw_transaction(&secret_key);
    let extra_info = get_chain_info_enc(&txaux);

    expect_error(
        &verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &root,
            &storage,
            &accounts,
        ),
        Error::AccountJailed,
    );

    // Deposit transaction

    let txaux = prepare_deposit_transaction(&secret_key, address.clone(), &merkle_tree);
    let extra_info = get_chain_info_enc(&txaux);

    expect_error(
        &verify_enclave_tx(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &root,
            &storage,
            &accounts,
        ),
        Error::AccountJailed,
    );

    // Unbond transaction

    let txaux = prepare_unbond_transaction(
        &secret_key,
        StakedStateAddress::BasicRedeem(address.clone()),
    );
    let extra_info = get_chain_info(&txaux);

    expect_error_unbond(
        &verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &root,
            &accounts,
        ),
        UnbondError::IsJailed,
    );

    // Node join transaction

    let (txaux, _) = prepare_nodejoin_transaction(
        &secret_key,
        StakedStateAddress::BasicRedeem(address.clone()),
    );
    let extra_info = get_chain_info(&txaux);

    expect_error_joinnode(
        &verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &root,
            &accounts,
        ),
        NodeJoinError::IsJailed,
    );
}

#[test]
fn check_unjail_transaction() {
    let (_db, accounts, secret_key, address, _merkle_tree, root) = prepare_jailed_accounts();

    // Incorrect nonce

    let txaux = prepare_unjail_transaction(
        &secret_key,
        StakedStateAddress::BasicRedeem(address.clone()),
        0,
    );
    let extra_info = get_chain_info(&txaux);

    expect_error_public(
        &verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &root,
            &accounts,
        ),
        PublicTxError::IncorrectNonce,
    );

    // Before `jailed_until`

    let txaux = prepare_unjail_transaction(
        &secret_key,
        StakedStateAddress::BasicRedeem(address.clone()),
        1,
    );
    let extra_info = get_chain_info(&txaux);

    expect_error_unjail(
        &verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &root,
            &accounts,
        ),
        UnjailError::JailTimeNotExpired,
    );

    // After `jailed_until`

    let txaux = prepare_unjail_transaction(
        &secret_key,
        StakedStateAddress::BasicRedeem(address.clone()),
        1,
    );
    let extra_info = ChainInfo {
        min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
            .calculate_for_txaux(&txaux)
            .expect("invalid fee policy"),
        chain_hex_id: DEFAULT_CHAIN_ID,
        block_time: 101,
        block_height: BlockHeight::genesis(),
        unbonding_period: 1,
    };

    let (fee, new_account) = verify_public_tx(
        &txaux,
        extra_info,
        NodeInfoWrap::default(),
        &root,
        &accounts,
    )
    .expect("Verification of unjail transaction failed");

    assert_eq!(Fee::new(Coin::zero()), fee);
    assert!(!new_account.unwrap().is_jailed());
}

fn prepare_nodejoin_transaction(
    secret_key: &SecretKey,
    address: StakedStateAddress,
) -> (TxAux, NodeJoinRequestTx) {
    let secp = Secp256k1::new();

    let tx = NodeJoinRequestTx {
        nonce: 1,
        address,
        attributes: StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
        node_meta: CouncilNode {
            name: "test".to_string(),
            security_contact: None,
            consensus_pubkey: TendermintValidatorPubKey::Ed25519([1u8; 32]),
        },
    };
    let witness = get_account_op_witness(secp, &tx.id(), &secret_key);

    (TxAux::NodeJoinTx(tx.clone(), witness), tx)
}

fn prepare_valid_nodejoin_tx(
    validator: bool,
) -> (
    TxAux,
    NodeJoinRequestTx,
    StakedStateAddress,
    SecretKey,
    AccountStorage,
    StarlingFixedKey,
) {
    let mut tree = AccountStorage::new(Storage::new_db(create_db()), 20).expect("account db");
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let addr = RedeemAddress::from(&public_key);
    let account = StakedState::new(
        1,
        Coin::one(),
        Coin::zero(),
        0,
        addr.into(),
        if validator {
            Some(Validator::new(CouncilNode::new(
                TendermintValidatorPubKey::Ed25519([1u8; 32]),
            )))
        } else {
            None
        },
    );
    let key = account.key();
    let wrapped = AccountWrapper(account);
    let new_root = tree
        .insert(None, &mut [key], &mut vec![wrapped])
        .expect("insert");
    let (txaux, tx) = prepare_nodejoin_transaction(&secret_key, addr.into());
    (txaux, tx, addr.into(), secret_key, tree, new_root)
}

#[test]
fn test_nodejoin_success() {
    let (txaux, _, _, _, accounts, root) = prepare_valid_nodejoin_tx(false);
    let extra_info = get_chain_info(&txaux);

    let (fee, new_account) = verify_public_tx(
        &txaux,
        extra_info,
        NodeInfoWrap::default(),
        &root,
        &accounts,
    )
    .expect("Verification of node join transaction failed");

    assert_eq!(Fee::new(Coin::zero()), fee);
    assert!(new_account.unwrap().validator.is_some());
}

#[test]
fn test_nodejoin_fail() {
    let (txaux, tx, _addr, secret_key, accounts, root) = prepare_valid_nodejoin_tx(false);
    let extra_info = get_chain_info(&txaux);
    // WrongChainHexId
    {
        let mut extra_info = extra_info.clone();
        extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
        let result = verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &root,
            &accounts,
        );
        expect_error_public(&result, PublicTxError::WrongChainHexId);
    }
    // UnsupportedVersion
    {
        let mut tx = tx.clone();
        tx.attributes.app_version = chain_core::APP_VERSION + 1;
        let txaux = TxAux::NodeJoinTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &root,
            &accounts,
        );
        expect_error_public(&result, PublicTxError::UnsupportedVersion);
    }
    // AccountNotFound, not exist account treated as empty account, so incorrect nonce
    {
        let result = verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &[0; 32],
            &accounts,
        );
        expect_error_public(&result, PublicTxError::IncorrectNonce);
    }
    // AccountIncorrectNonce
    {
        let mut tx = tx.clone();
        tx.nonce = 0;
        let txaux = TxAux::NodeJoinTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &root,
            &accounts,
        );
        expect_error_public(&result, PublicTxError::IncorrectNonce);
    }
    // MismatchAccountAddress
    {
        let mut tx = tx.clone();
        tx.address = StakedStateAddress::from(RedeemAddress::from([1u8; 20]));
        let txaux = TxAux::NodeJoinTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(
            &txaux,
            extra_info,
            NodeInfoWrap::default(),
            &root,
            &accounts,
        );
        expect_error_public(&result, PublicTxError::StakingWitnessNotMatch);
    }
    // BondedNotEnough
    {
        let wrap = NodeInfoWrap::custom((Coin::one() + Coin::one()).unwrap(), Vec::new());
        let result = verify_public_tx(&txaux, extra_info, wrap, &root, &accounts);
        expect_error_joinnode(&result, NodeJoinError::BondedNotEnough);
    }
    let (txaux, _tx, addr, _secret_key, accounts, root) = prepare_valid_nodejoin_tx(true);
    // AlreadyJoined
    {
        let wrap = NodeInfoWrap::custom(Coin::one(), vec![addr]);
        let result = verify_public_tx(&txaux, extra_info, wrap, &root, &accounts);
        expect_error_joinnode(&result, NodeJoinError::AlreadyJoined);
    }
}
