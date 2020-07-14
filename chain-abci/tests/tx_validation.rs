use std::collections::HashMap;

use bit_vec::BitVec;
/// FIXME: organize better / refactor (group by tx, less duplication or unneeded arguments)
use chain_abci::enclave_bridge::mock::MockClient;
use chain_abci::enclave_bridge::EnclaveProxy;
use chain_abci::staking::StakingTable;
use chain_abci::storage::{
    process_public_tx, verify_enclave_tx as verify_enclave_tx_inner, TxEnclaveAction,
};
use chain_abci::tx_error::{NodeJoinError, PublicTxError, TxError, UnbondError, UnjailError};
use chain_core::common::{MerkleTree, Timespec};
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::{Coin, CoinError};
use chain_core::state::account::StakedState;
use chain_core::state::account::StakedStateAddress;
use chain_core::state::account::StakedStateOpAttributes;
use chain_core::state::account::{
    DepositBondTx, NodeMetadata, StakedStateOpWitness, UnbondTx, UnjailTx, Validator,
    WithdrawUnbondedTx,
};
use chain_core::state::tendermint::BlockHeight;
use chain_core::state::tendermint::TendermintValidatorPubKey;
use chain_core::state::validator::NodeJoinRequestTx;
use chain_core::tx::data::{
    address::ExtendedAddr,
    attribute::TxAttributes,
    input::{TxoPointer, TxoSize},
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
use chain_core::tx::{TxAux, TxEnclaveAux, TxPublicAux};
use chain_storage::buffer::Get;
use chain_storage::jellyfish::{StakingBufferStore, StakingGetter, Version};
use chain_storage::{Storage, COL_ENCLAVE_TX, COL_TX_META, NUM_COLUMNS};
use chain_tx_validation::{
    verify_bonded_deposit_core, verify_transfer, verify_unbonded_withdraw_core, ChainInfo, Error,
    TxWithOutputs,
};
use kvdb::KeyValueDB;
use kvdb_memorydb::create;
use mock_utils::{encrypt, encrypt_payload, seal};
use secp256k1::schnorrsig::schnorr_sign;
use secp256k1::{key::PublicKey, key::SecretKey, key::XOnlyPublicKey, Message, Secp256k1, Signing};
use std::fmt::Debug;
use std::mem;
use std::sync::Arc;
use test_common::chain_env::{mock_confidential_init, mock_council_node_meta};

fn verify_enclave_tx<T: EnclaveProxy>(
    tx_validator: &mut T,
    txaux: &TxEnclaveAux,
    extra_info: &ChainInfo,
    version: Version,
    storage: &Storage,
) -> Result<TxEnclaveAction, Error> {
    verify_enclave_tx_inner(
        tx_validator,
        txaux,
        &extra_info,
        &StakingGetter::new(storage, version),
        storage,
    )
}

fn verify_public_tx(
    txaux: &TxPublicAux,
    extra_info: &ChainInfo,
    info: NodeInfoWrap,
    version: Version,
    storage: &Storage,
) -> Result<(Fee, Option<StakedState>), TxError> {
    let mut tbl =
        StakingTable::from_genesis(&StakingGetter::new(storage, version), info.0, 50, &info.1);
    let mut buffer = HashMap::new();

    let mut store = StakingBufferStore::new(StakingGetter::new(storage, version), &mut buffer);
    let tx_action = process_public_tx(&mut store, &mut tbl, 0, extra_info, txaux)?;

    let fee = tx_action.fee();
    let maddress = tx_action.staking_address();
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
    let signature = schnorr_sign(&secp, &message, secret_key, &mut rand::thread_rng());

    TxInWitness::TreeSig(signature, proof)
}

pub fn get_account_op_witness<C: Signing>(
    secp: Secp256k1<C>,
    txid: &TxId,
    secret_key: &SecretKey,
) -> StakedStateOpWitness {
    let message = Message::from_slice(&txid[..]).expect("32 bytes");
    let sig = secp.sign_recoverable(&message, &secret_key);
    StakedStateOpWitness::new(sig)
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
        min_fee_computed: LinearFee::new(
            Milli::try_new(1, 1).unwrap(),
            Milli::try_new(1, 1).unwrap(),
        )
        .calculate_for_txaux(&txaux)
        .expect("invalid fee policy"),
        chain_hex_id: DEFAULT_CHAIN_ID,
        block_time: 0,
        block_height: BlockHeight::genesis(),
        max_evidence_age: 1,
    }
}

fn get_chain_info_enc(txaux: &TxEnclaveAux) -> ChainInfo {
    get_chain_info(&TxAux::EnclaveTx(txaux.clone()))
}

fn get_chain_info_pub(txaux: &TxPublicAux) -> ChainInfo {
    get_chain_info(&TxAux::PublicTx(txaux.clone()))
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
    inittx.put(
        COL_ENCLAVE_TX,
        &old_tx_id[..],
        &seal(&TxWithOutputs::Transfer(old_tx)),
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
    Storage,
) {
    let (db, txp, addr, merkle_tree, secret_key) = prepate_init_tx(timelocked);
    let secp = Secp256k1::new();
    let mut tx = Tx::new();
    tx.add_input(txp);
    tx.add_output(TxOut::new(addr, Coin::new(9).unwrap()));
    let sk2 = SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order");
    let addr2 = get_address(&secp, &sk2).0;
    tx.add_output(TxOut::new(addr2, Coin::new(99999649).unwrap()));

    let witness: Vec<TxInWitness> = vec![get_tx_witness(secp, &tx.id(), &secret_key, &merkle_tree)];
    let plain_txaux = PlainTxAux::new(tx.clone(), witness.clone().into());
    let txaux = TxEnclaveAux::TransferTx {
        inputs: tx.inputs.clone(),
        no_of_outputs: tx.outputs.len() as TxoSize,
        payload: encrypt(&plain_txaux, tx.id()),
    };
    (
        db.clone(),
        txaux,
        tx,
        witness.into(),
        merkle_tree,
        secret_key,
        Storage::new_db(db),
    )
}

fn prepare_app_valid_unbond_tx() -> (TxPublicAux, UnbondTx, SecretKey, Storage) {
    let mut storage = Storage::new_db(create_db());
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let addr = RedeemAddress::from(&public_key);
    let account = StakedState::new(1, Coin::one(), Coin::zero(), 0, addr.into(), None);
    storage.put_stakings(0, &[account]);
    let tx = UnbondTx::new(
        addr.into(),
        1,
        Coin::new(9).unwrap(),
        StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
    );
    let witness = get_account_op_witness(secp, &tx.id(), &secret_key);
    let txaux = TxPublicAux::UnbondStakeTx(tx.clone(), witness);
    (txaux, tx, secret_key, storage)
}

#[test]
fn existing_account_unbond_tx_should_verify() {
    let (txaux, _, _, storage) = prepare_app_valid_unbond_tx();
    let extra_info = get_chain_info_pub(&txaux);
    let result = verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage);
    assert!(result.is_ok());
}

#[test]
fn test_account_unbond_verify_fail() {
    let (txaux, tx, secret_key, storage) = prepare_app_valid_unbond_tx();
    let extra_info = get_chain_info_pub(&txaux);
    // WrongChainHexId
    {
        let mut extra_info = extra_info;
        extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
        let result = verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage);
        expect_error_public(&result, PublicTxError::WrongChainHexId);
    }
    // UnsupportedVersion
    {
        let mut tx = tx.clone();
        tx.attributes.app_version = chain_core::APP_VERSION + 1;
        let txaux = TxPublicAux::UnbondStakeTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage);
        expect_error_public(&result, PublicTxError::UnsupportedVersion);
    }
    // AccountNotFound, non exist account treated as a default account, so incorrect nonce.
    {
        let result = verify_public_tx(
            &txaux,
            &extra_info,
            NodeInfoWrap::default(),
            0,
            &create_storage(),
        );
        expect_error_public(&result, PublicTxError::IncorrectNonce);
    }
    // AccountIncorrectNonce
    {
        let mut tx = tx.clone();
        tx.nonce = 0;
        let txaux = TxPublicAux::UnbondStakeTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage);
        expect_error_public(&result, PublicTxError::IncorrectNonce);
    }
    // ZeroCoin
    {
        let mut tx = tx.clone();
        tx.value = Coin::zero();
        let txaux = TxPublicAux::UnbondStakeTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage);
        expect_error_unbond(&result, UnbondError::ZeroValue);
    }
    // InputOutputDoNotMatch
    {
        let mut tx = tx;
        tx.value = (tx.value + Coin::one()).unwrap();
        let txaux = TxPublicAux::UnbondStakeTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage);
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
    Storage,
) {
    let mut storage = create_storage();
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
    storage.put_stakings(0, &[account.clone()]);

    let sk2 = SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order");

    let addr1 = get_address(&secp, &secret_key).0;
    let addr2 = get_address(&secp, &sk2).0;

    let outputs = vec![
        TxOut::new_with_timelock(addr1, Coin::new(9).unwrap(), 0),
        TxOut::new_with_timelock(addr2, Coin::new(99999728).unwrap(), 0),
    ];

    let tx = WithdrawUnbondedTx::new(1, outputs, TxAttributes::new(DEFAULT_CHAIN_ID));
    let witness = get_account_op_witness(secp, &tx.id(), &secret_key);
    let txaux = TxEnclaveAux::WithdrawUnbondedStakeTx {
        no_of_outputs: tx.outputs.len() as TxoSize,
        witness: witness.clone(),
        payload: encrypt(&PlainTxAux::WithdrawUnbondedStakeTx(tx.clone()), tx.id()),
    };
    (txaux, tx, witness, account, secret_key, storage)
}

#[test]
fn existing_account_withdraw_tx_should_verify() {
    let (txaux, _, _, _, _, storage) = prepare_app_valid_withdraw_tx(0);
    let extra_info = get_chain_info_enc(&txaux);
    verify_enclave_tx(
        &mut get_enclave_bridge_mock(),
        &txaux,
        &extra_info,
        0,
        &storage,
    )
    .unwrap();
}

#[test]
fn test_account_withdraw_verify_fail() {
    let (txaux, tx, _, account, secret_key, storage) = prepare_app_valid_withdraw_tx(0);
    let extra_info = get_chain_info_enc(&txaux);
    let mut mock_bridge = get_enclave_bridge_mock();
    // WrongChainHexId
    {
        let mut extra_info = extra_info;
        extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, &extra_info, &account);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, &extra_info, &account);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, &extra_info, &account);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, &extra_info, &account);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, &extra_info, &account);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, &extra_info, &account);
        expect_error(&result, Error::InputOutputDoNotMatch);
    }
    // AccountNotFound
    {
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &create_storage());
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, &extra_info, &account);
        expect_error(&result, Error::AccountIncorrectNonce);
    }
    // AccountWithdrawOutputNotLocked
    {
        let mut tx = tx.clone();
        tx.outputs[0].valid_from = None;
        let witness = get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key);
        let txaux = replace_tx_payload(
            txaux,
            PlainTxAux::WithdrawUnbondedStakeTx(tx.clone()),
            Some(witness),
            None,
        );
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, &extra_info, &account);
        expect_error(&result, Error::AccountWithdrawOutputNotLocked);
    }
    // AccountNotUnbonded
    {
        let (txaux, _, _, account, _, storage) = prepare_app_valid_withdraw_tx(20);
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_unbonded_withdraw_core(&tx, &extra_info, &account);
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
    Storage,
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
    let txaux = TxEnclaveAux::DepositStakeTx {
        tx: tx.clone(),
        payload: encrypt(&PlainTxAux::DepositStakeTx(witness.clone().into()), tx.id()),
    };
    (
        db.clone(),
        txaux,
        tx,
        witness.into(),
        secret_key,
        Storage::new_db(db),
    )
}

const DEFAULT_CHAIN_ID: u8 = 0;

#[test]
fn existing_utxo_input_tx_should_verify() {
    let mut mock_bridge = get_enclave_bridge_mock();
    let (_, txaux, _, _, _, _, storage) = prepare_app_valid_transfer_tx(false);
    let extra_info = get_chain_info_enc(&txaux);
    verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage).unwrap();
    let (_, txaux, _, _, _, storage) = prepare_app_valid_deposit_tx(false);
    verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage).unwrap();
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
    let (db, txaux, tx, witness, secret_key, storage) = prepare_app_valid_deposit_tx(false);
    let extra_info = get_chain_info_enc(&txaux);
    // WrongChainHexId
    {
        let mut extra_info = extra_info;
        extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &witness, &extra_info, vec![]);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &witness, &extra_info, vec![]);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &witness, &extra_info, vec![]);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &witness, &extra_info, vec![]);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &witness, &extra_info, vec![]);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &vec![].into(), &extra_info, vec![]);
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

        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
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
            &extra_info,
            vec![TxWithOutputs::Transfer(input_tx)],
        );
        expect_error(
            &result,
            Error::EcdsaCrypto, // FIXME: Error::EcdsaCrypto(secp256k1::Error::InvalidPublicKey),
        );
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::DepositStakeTx(witness),
            None,
            None,
        );
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
    }
    // InvalidInput
    {
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &create_storage());
        expect_error(&result, Error::InvalidInput);
    }
    // InputOutputDoNotMatch
    {
        let mut extra_info = extra_info;
        extra_info.min_fee_computed = Fee::new(Coin::one());
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_bonded_deposit_core(&tx, &witness, &extra_info, vec![]);
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
            no_of_outputs: tx.outputs.len() as TxoSize,
            payload: TxObfuscated {
                txid: tx.id(),
                key_from,
                init_vector,
                txpayload: encrypt_payload(&plain_tx),
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
                txpayload: encrypt_payload(&plain_tx),
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
            no_of_outputs: tx.outputs.len() as TxoSize,
            witness: if let Some(w) = mwitness { w } else { witness },
            payload: TxObfuscated {
                txid: tx.id(),
                key_from,
                init_vector,
                txpayload: encrypt_payload(&plain_tx),
            },
        },
        _ => unreachable!(),
    }
}

#[test]
fn test_transfer_verify_fail() {
    let mut mock_bridge = get_enclave_bridge_mock();
    let (db, txaux, tx, witness, merkle_tree, secret_key, storage) =
        prepare_app_valid_transfer_tx(false);
    let extra_info = get_chain_info_enc(&txaux);
    // WrongChainHexId
    {
        let mut extra_info = extra_info;
        extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_transfer(&tx, &witness, &extra_info, vec![]);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        expect_error(&result, Error::NoInputs);
    }
    // NoOutputs
    {
        let mut tx = tx.clone();
        tx.outputs.clear();
        let result = verify_transfer(&tx, &witness, &extra_info, vec![]);
        expect_error(&result, Error::NoOutputs);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx, witness.clone()),
            None,
            None,
        );
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
    }
    // DuplicateInputs
    {
        let mut tx = tx.clone();
        let inp = tx.inputs[0].clone();
        tx.inputs.push(inp);
        let result = verify_transfer(&tx, &witness, &extra_info, vec![]);
        expect_error(&result, Error::DuplicateInputs);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx, witness.clone()),
            None,
            None,
        );
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
    }
    // ZeroCoin
    {
        let mut tx = tx.clone();
        tx.outputs[0].value = Coin::zero();
        let result = verify_transfer(&tx, &witness, &extra_info, vec![]);
        expect_error(&result, Error::ZeroCoin);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx, witness.clone()),
            None,
            None,
        );
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
    }
    // UnexpectedWitnesses
    {
        let mut witness = witness.clone();
        let wp = witness[0].clone();
        witness.push(wp);
        let result = verify_transfer(&tx, &witness, &extra_info, vec![]);
        expect_error(&result, Error::UnexpectedWitnesses);
        let txaux = replace_tx_payload(
            txaux.clone(),
            PlainTxAux::TransferTx(tx.clone(), witness),
            None,
            None,
        );
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
        let result = verify_transfer(&tx.clone(), &vec![].into(), &extra_info, vec![]);
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
        let result = verify_transfer(&tx, &witness, &extra_info, vec![]);
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
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

        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
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
            &extra_info,
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
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
    }
    // InvalidInput
    {
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &create_storage());
        expect_error(&result, Error::InvalidInput);
    }
    // InputOutputDoNotMatch
    {
        let mut tx = tx;
        let mut witness = witness;

        tx.outputs[0].value = (tx.outputs[0].value + Coin::one()).unwrap();
        witness[0] = get_tx_witness(Secp256k1::new(), &tx.id(), &secret_key, &merkle_tree);
        let result = verify_transfer(&tx, &witness, &extra_info, vec![]);
        expect_error(&result, Error::InputOutputDoNotMatch);
        let txaux = replace_tx_payload(txaux, PlainTxAux::TransferTx(tx, witness), None, None);
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
    }
    // OutputInTimelock
    {
        let (_, txaux, tx, witness, _, _, storage) = prepare_app_valid_transfer_tx(true);
        let addr = get_address(&Secp256k1::new(), &secret_key).0;
        let input_tx = get_old_tx(addr, true);
        let result = verify_transfer(
            &tx,
            &witness,
            &extra_info,
            vec![TxWithOutputs::Transfer(input_tx)],
        );
        expect_error(&result, Error::OutputInTimelock);
        let result = verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage);
        assert!(result.is_err());
    }
}

fn prepare_jailed_accounts() -> (
    Storage,
    SecretKey,
    RedeemAddress,
    MerkleTree<RawXOnlyPubkey>,
) {
    let mut storage = create_storage();

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
            council_node: mock_council_node_meta(TendermintValidatorPubKey::Ed25519([0xcd; 32])),
            jailed_until: Some(100),
            inactive_time: Some(0),
            inactive_block: Some(BlockHeight::genesis()),
            used_validator_addresses: vec![],
        }),
    );

    storage.put_stakings(0, &[account]);

    (storage, secret_key, addr, merkle_tree)
}

fn prepare_withdraw_transaction(secret_key: &SecretKey) -> TxEnclaveAux {
    let secp = Secp256k1::new();

    let tx = WithdrawUnbondedTx::new(1, vec![], TxAttributes::new(DEFAULT_CHAIN_ID));
    let witness = get_account_op_witness(secp, &tx.id(), secret_key);

    TxEnclaveAux::WithdrawUnbondedStakeTx {
        no_of_outputs: tx.outputs.len() as TxoSize,
        witness,
        payload: encrypt(&PlainTxAux::WithdrawUnbondedStakeTx(tx.clone()), tx.id()),
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
        payload: encrypt(&PlainTxAux::DepositStakeTx(witness.into()), tx.id()),
    }
}

fn prepare_unbond_transaction(secret_key: &SecretKey, address: StakedStateAddress) -> TxPublicAux {
    let secp = Secp256k1::new();

    let tx = UnbondTx::new(
        address,
        1,
        Coin::new(9).unwrap(),
        StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
    );
    let witness = get_account_op_witness(secp, &tx.id(), &secret_key);

    TxPublicAux::UnbondStakeTx(tx, witness)
}

fn prepare_unjail_transaction(
    secret_key: &SecretKey,
    address: StakedStateAddress,
    nonce: u64,
) -> TxPublicAux {
    let secp = Secp256k1::new();

    let tx = UnjailTx {
        nonce,
        address,
        attributes: StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
    };
    let witness = get_account_op_witness(secp, &tx.id(), &secret_key);

    TxPublicAux::UnjailTx(tx, witness)
}

#[test]
fn check_verify_fail_for_jailed_account() {
    let mut mock_bridge = get_enclave_bridge_mock();
    let (storage, secret_key, address, merkle_tree) = prepare_jailed_accounts();
    // Withdraw transaction

    let txaux = prepare_withdraw_transaction(&secret_key);
    let extra_info = get_chain_info_enc(&txaux);

    expect_error(
        &verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage),
        Error::AccountJailed,
    );

    // Deposit transaction

    let txaux = prepare_deposit_transaction(&secret_key, address, &merkle_tree);
    let extra_info = get_chain_info_enc(&txaux);

    expect_error(
        &verify_enclave_tx(&mut mock_bridge, &txaux, &extra_info, 0, &storage),
        Error::AccountJailed,
    );

    // Unbond transaction

    let txaux = prepare_unbond_transaction(&secret_key, StakedStateAddress::BasicRedeem(address));
    let extra_info = get_chain_info_pub(&txaux);

    expect_error_unbond(
        &verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage),
        UnbondError::IsJailed,
    );

    // Node join transaction

    let (txaux, _) =
        prepare_nodejoin_transaction(&secret_key, StakedStateAddress::BasicRedeem(address));
    let extra_info = get_chain_info_pub(&txaux);

    expect_error_joinnode(
        &verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage),
        NodeJoinError::IsJailed,
    );
}

#[test]
fn check_unjail_transaction() {
    let (storage, secret_key, address, _merkle_tree) = prepare_jailed_accounts();

    // Incorrect nonce

    let txaux =
        prepare_unjail_transaction(&secret_key, StakedStateAddress::BasicRedeem(address), 0);
    let extra_info = get_chain_info_pub(&txaux);

    expect_error_public(
        &verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage),
        PublicTxError::IncorrectNonce,
    );

    // Before `jailed_until`

    let txaux =
        prepare_unjail_transaction(&secret_key, StakedStateAddress::BasicRedeem(address), 1);
    let extra_info = get_chain_info_pub(&txaux);

    expect_error_unjail(
        &verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage),
        UnjailError::JailTimeNotExpired,
    );

    // After `jailed_until`

    let txaux =
        prepare_unjail_transaction(&secret_key, StakedStateAddress::BasicRedeem(address), 1);
    let extra_info = ChainInfo {
        min_fee_computed: LinearFee::new(
            Milli::try_new(1, 1).unwrap(),
            Milli::try_new(1, 1).unwrap(),
        )
        .calculate_for_txaux(&TxAux::PublicTx(txaux.clone()))
        .expect("invalid fee policy"),
        chain_hex_id: DEFAULT_CHAIN_ID,
        block_time: 101,
        block_height: BlockHeight::genesis(),
        max_evidence_age: 0,
    };

    let (fee, new_account) =
        verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage)
            .expect("Verification of unjail transaction failed");

    assert_eq!(Fee::new(Coin::zero()), fee);
    assert!(!new_account.unwrap().is_jailed());
}

fn prepare_nodejoin_transaction(
    secret_key: &SecretKey,
    address: StakedStateAddress,
) -> (TxPublicAux, NodeJoinRequestTx) {
    let secp = Secp256k1::new();

    let tx = NodeJoinRequestTx {
        nonce: 1,
        address,
        attributes: StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
        node_meta: NodeMetadata::new_council_node_with_details(
            "test".to_string(),
            None,
            TendermintValidatorPubKey::Ed25519([1u8; 32]),
            mock_confidential_init(),
        ),
    };
    let witness = get_account_op_witness(secp, &tx.id(), &secret_key);

    (TxPublicAux::NodeJoinTx(tx.clone(), witness), tx)
}

fn prepare_valid_nodejoin_tx(
    validator: bool,
) -> (
    TxPublicAux,
    NodeJoinRequestTx,
    StakedStateAddress,
    SecretKey,
    Storage,
) {
    let mut storage = Storage::new_db(create_db());
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
            Some(Validator::new(mock_council_node_meta(
                TendermintValidatorPubKey::Ed25519([1u8; 32]),
            )))
        } else {
            None
        },
    );
    storage.put_stakings(0, &[account]);
    let (txaux, tx) = prepare_nodejoin_transaction(&secret_key, addr.into());
    (txaux, tx, addr.into(), secret_key, storage)
}

#[test]
fn test_nodejoin_success() {
    let (txaux, _, _, _, storage) = prepare_valid_nodejoin_tx(false);
    let extra_info = get_chain_info_pub(&txaux);

    let (fee, new_account) =
        verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage)
            .expect("Verification of node join transaction failed");

    assert_eq!(Fee::new(Coin::zero()), fee);
    assert!(new_account.unwrap().node_meta.is_some());
}

#[test]
fn test_nodejoin_fail() {
    let (txaux, tx, _addr, secret_key, storage) = prepare_valid_nodejoin_tx(false);
    let extra_info = get_chain_info_pub(&txaux);
    // WrongChainHexId
    {
        let mut extra_info = extra_info;
        extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
        let result = verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage);
        expect_error_public(&result, PublicTxError::WrongChainHexId);
    }
    // UnsupportedVersion
    {
        let mut tx = tx.clone();
        tx.attributes.app_version = chain_core::APP_VERSION + 1;
        let txaux = TxPublicAux::NodeJoinTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage);
        expect_error_public(&result, PublicTxError::UnsupportedVersion);
    }
    // AccountNotFound, not exist account treated as empty account, so incorrect nonce
    {
        let result = verify_public_tx(
            &txaux,
            &extra_info,
            NodeInfoWrap::default(),
            0,
            &create_storage(),
        );
        expect_error_public(&result, PublicTxError::IncorrectNonce);
    }
    // AccountIncorrectNonce
    {
        let mut tx = tx.clone();
        tx.nonce = 0;
        let txaux = TxPublicAux::NodeJoinTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage);
        expect_error_public(&result, PublicTxError::IncorrectNonce);
    }
    // MismatchAccountAddress
    {
        let mut tx = tx;
        tx.address = StakedStateAddress::from(RedeemAddress::from([1u8; 20]));
        let txaux = TxPublicAux::NodeJoinTx(
            tx.clone(),
            get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
        );
        let result = verify_public_tx(&txaux, &extra_info, NodeInfoWrap::default(), 0, &storage);
        expect_error_public(&result, PublicTxError::StakingWitnessNotMatch);
    }
    // BondedNotEnough
    {
        let wrap = NodeInfoWrap::custom((Coin::one() + Coin::one()).unwrap(), Vec::new());
        let result = verify_public_tx(&txaux, &extra_info, wrap, 0, &storage);
        expect_error_joinnode(&result, NodeJoinError::BondedNotEnough);
    }
    let (txaux, _tx, addr, _secret_key, storage) = prepare_valid_nodejoin_tx(true);
    // AlreadyJoined
    {
        let wrap = NodeInfoWrap::custom(Coin::one(), vec![addr]);
        let result = verify_public_tx(&txaux, &extra_info, wrap, 0, &storage);
        expect_error_joinnode(&result, NodeJoinError::AlreadyJoined);
    }
}
