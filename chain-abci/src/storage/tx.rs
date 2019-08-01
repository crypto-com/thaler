use crate::enclave_bridge::EnclaveProxy;
use crate::storage::account::AccountStorage;
use crate::storage::account::AccountWrapper;
use crate::storage::COL_TX_META;
use bit_vec::BitVec;
use chain_core::state::account::{to_stake_key, StakedState, StakedStateAddress};
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::fee::Fee;
use chain_core::tx::TransactionId;
use chain_core::tx::TxAux;
use chain_tx_validation::{verify_unbonding, witness::verify_tx_recover_address, ChainInfo, Error};
use enclave_protocol::{EnclaveRequest, EnclaveResponse};
use kvdb::KeyValueDB;
use starling::constants::KEY_LEN;
use std::sync::Arc;

/// key type for looking up accounts/staked states in the merkle tree storage
pub type StarlingFixedKey = [u8; KEY_LEN];

/// checks that the account can be retrieved from the trie storage
pub fn get_account(
    account_address: &StakedStateAddress,
    last_root: &StarlingFixedKey,
    accounts: &AccountStorage,
) -> Result<StakedState, Error> {
    let account_key = to_stake_key(account_address);
    let items = accounts.get(last_root, &mut [&account_key]);
    if let Err(e) = items {
        return Err(Error::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            e,
        )));
    }
    let account = items.unwrap()[&account_key].clone();
    match account {
        None => Err(Error::AccountNotFound),
        Some(AccountWrapper(a)) => Ok(a),
    }
}

fn check_spent_input_lookup(inputs: &[TxoPointer], db: Arc<dyn KeyValueDB>) -> Result<(), Error> {
    // check that there are inputs
    if inputs.is_empty() {
        return Err(Error::NoInputs);
    }
    for txin in inputs.iter() {
        let txo = db.get(COL_TX_META, &txin.id[..]);
        match txo {
            Ok(Some(v)) => {
                let input_index = txin.index as usize;
                let bv = BitVec::from_bytes(&v).get(input_index);
                if bv.is_none() {
                    return Err(Error::InvalidInput);
                }
                if bv.unwrap() {
                    return Err(Error::InputSpent);
                }
            }
            Ok(None) => {
                return Err(Error::InvalidInput);
            }
            Err(e) => {
                return Err(Error::IoError(e));
            }
        }
    }
    Ok(())
}

/// Checks TX against the current DB and returns an `Error` if something fails.
/// If OK, returns the paid fee.
pub fn verify<T: EnclaveProxy>(
    tx_validator: &mut T,
    txaux: &TxAux,
    extra_info: ChainInfo,
    last_account_root_hash: &StarlingFixedKey,
    db: Arc<dyn KeyValueDB>,
    accounts: &AccountStorage,
) -> Result<(Fee, Option<StakedState>), Error> {
    let paid_fee = match txaux {
        TxAux::TransferTx { inputs, .. } => {
            check_spent_input_lookup(&inputs, db)?;
            let response = tx_validator.process_request(EnclaveRequest::VerifyTx {
                tx: txaux.clone(),
                account: None,
                info: extra_info,
            });
            match response {
                EnclaveResponse::VerifyTx(Ok(r)) => r,
                _ => {
                    return Err(Error::EnclaveRejected);
                }
            }
        }
        TxAux::DepositStakeTx { tx, .. } => {
            let maccount = get_account(&tx.to_staked_account, last_account_root_hash, accounts);
            let account = match maccount {
                Ok(a) => Some(a),
                Err(Error::AccountNotFound) => None,
                Err(e) => {
                    return Err(e);
                }
            };
            check_spent_input_lookup(&tx.inputs, db)?;
            let response = tx_validator.process_request(EnclaveRequest::VerifyTx {
                tx: txaux.clone(),
                account,
                info: extra_info,
            });
            match response {
                EnclaveResponse::VerifyTx(Ok(r)) => r,
                _ => {
                    return Err(Error::EnclaveRejected);
                }
            }
        }
        TxAux::UnbondStakeTx(maintx, witness) => {
            let account_address = verify_tx_recover_address(&witness, &maintx.id());
            if let Err(e) = account_address {
                return Err(Error::EcdsaCrypto(e));
            }
            let account = get_account(&account_address.unwrap(), last_account_root_hash, accounts)?;
            verify_unbonding(maintx, extra_info, account)?
        }
        TxAux::WithdrawUnbondedStakeTx { txid, witness, .. } => {
            let account_address = verify_tx_recover_address(&witness, &txid);
            if let Err(e) = account_address {
                return Err(Error::EcdsaCrypto(e));
            }
            let account = get_account(&account_address.unwrap(), last_account_root_hash, accounts)?;
            let response = tx_validator.process_request(EnclaveRequest::VerifyTx {
                tx: txaux.clone(),
                account: Some(account),
                info: extra_info,
            });
            match response {
                EnclaveResponse::VerifyTx(Ok(r)) => r,
                _ => {
                    return Err(Error::EnclaveRejected);
                }
            }
        }
    };
    Ok(paid_fee)
}

/// FIXME: probably move the tests to chain-tx-validation and keep here only the small parts related to abci (looking up accounts, checking double spends...)
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::enclave_bridge::mock::MockClient;
    use crate::storage::{Storage, COL_TX_META, NUM_COLUMNS};
    use chain_core::common::{MerkleTree, Timespec};
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::{Coin, CoinError};
    use chain_core::state::account::StakedStateOpAttributes;
    use chain_core::state::account::{
        DepositBondTx, StakedStateOpWitness, UnbondTx, WithdrawUnbondedTx,
    };
    use chain_core::tx::data::{
        address::ExtendedAddr,
        attribute::TxAttributes,
        input::{TxoIndex, TxoPointer},
        output::TxOut,
    };
    use chain_core::tx::data::{Tx, TxId};
    use chain_core::tx::fee::FeeAlgorithm;
    use chain_core::tx::fee::{LinearFee, Milli};
    use chain_core::tx::witness::tree::RawPubkey;
    use chain_core::tx::witness::{TxInWitness, TxWitness};
    use chain_core::tx::PlainTxAux;
    use chain_core::tx::TxObfuscated;
    use chain_tx_validation::{
        verify_bonded_deposit, verify_transfer, verify_unbonded_withdraw, TxWithOutputs,
    };
    use kvdb_memorydb::create;
    use parity_scale_codec::Encode;
    use secp256k1::schnorrsig::schnorr_sign;
    use secp256k1::{key::PublicKey, key::SecretKey, Message, Secp256k1, Signing};
    use std::fmt::Debug;
    use std::mem;

    pub fn get_tx_witness<C: Signing>(
        secp: Secp256k1<C>,
        txid: &TxId,
        secret_key: &SecretKey,
        merkle_tree: &MerkleTree<RawPubkey>,
    ) -> TxInWitness {
        let message = Message::from_slice(txid).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, secret_key);
        let proof = merkle_tree
            .generate_proof(RawPubkey::from(public_key.serialize()))
            .unwrap();
        let signature = schnorr_sign(&secp, &message, secret_key).0;

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
        Arc::new(create(NUM_COLUMNS.unwrap()))
    }

    fn get_enclave_bridge_mock() -> MockClient {
        MockClient::new(DEFAULT_CHAIN_ID)
    }

    fn get_old_tx(addr: ExtendedAddr, timelocked: bool) -> Tx {
        let mut old_tx = Tx::new();

        if timelocked {
            old_tx.add_output(TxOut::new_with_timelock(addr, Coin::one(), 20));
        } else {
            old_tx.add_output(TxOut::new_with_timelock(addr, Coin::one(), -20));
        }
        old_tx
    }

    fn get_address<C: Signing>(
        secp: &Secp256k1<C>,
        secret_key: &SecretKey,
    ) -> (ExtendedAddr, MerkleTree<RawPubkey>) {
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let merkle_tree = MerkleTree::new(vec![RawPubkey::from(public_key.serialize())]);

        (ExtendedAddr::OrTree(merkle_tree.root_hash()), merkle_tree)
    }

    fn prepate_init_tx(
        timelocked: bool,
        mock_client: &mut MockClient,
    ) -> (
        Arc<dyn KeyValueDB>,
        TxoPointer,
        ExtendedAddr,
        MerkleTree<RawPubkey>,
        SecretKey,
    ) {
        let db = create_db();

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");

        let (addr, merkle_tree) = get_address(&secp, &secret_key);
        let old_tx = get_old_tx(addr.clone(), timelocked);

        let old_tx_id = old_tx.id();

        let mut inittx = db.transaction();
        mock_client
            .local_tx_store
            .insert(old_tx_id, TxWithOutputs::Transfer(old_tx));

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
        mock_client: &mut MockClient,
    ) -> (
        Arc<dyn KeyValueDB>,
        TxAux,
        Tx,
        TxWitness,
        MerkleTree<RawPubkey>,
        SecretKey,
        AccountStorage,
    ) {
        let (db, txp, addr, merkle_tree, secret_key) = prepate_init_tx(timelocked, mock_client);
        let secp = Secp256k1::new();
        let mut tx = Tx::new();
        tx.add_input(txp);
        tx.add_output(TxOut::new(addr, Coin::new(9).unwrap()));
        let sk2 = SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order");
        let addr2 = get_address(&secp, &sk2).0;
        tx.add_output(TxOut::new(addr2, Coin::new(1).unwrap()));

        let witness: Vec<TxInWitness> =
            vec![get_tx_witness(secp, &tx.id(), &secret_key, &merkle_tree)];
        let plain_txaux = PlainTxAux::new(tx.clone(), witness.clone().into());
        // TODO: mock enc
        let txaux = TxAux::TransferTx {
            txid: tx.id(),
            inputs: tx.inputs.clone(),
            no_of_outputs: tx.outputs.len() as TxoIndex,
            payload: TxObfuscated {
                key_from: 0,
                nonce: [0; 12],
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

    fn prepare_app_valid_unbond_tx(
    ) -> (TxAux, UnbondTx, SecretKey, AccountStorage, StarlingFixedKey) {
        let mut tree = AccountStorage::new(Storage::new_db(create_db()), 20).expect("account db");
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let addr = RedeemAddress::from(&public_key);
        let account = StakedState::new(1, Coin::one(), Coin::zero(), 0, addr.into());
        let key = account.key();
        let wrapped = AccountWrapper(account);
        let new_root = tree
            .insert(None, &mut [&key], &mut vec![&wrapped])
            .expect("insert");
        let tx = UnbondTx::new(
            Coin::new(9).unwrap(),
            1,
            StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
        );
        let witness = get_account_op_witness(secp, &tx.id(), &secret_key);
        let txaux = TxAux::UnbondStakeTx(tx.clone(), witness.clone());
        (txaux, tx.clone(), secret_key, tree, new_root)
    }

    #[test]
    fn existing_account_unbond_tx_should_verify() {
        let (txaux, _, _, accounts, last_account_root_hash) = prepare_app_valid_unbond_tx();
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            unbonding_period: 1,
        };
        let result = verify(
            &mut get_enclave_bridge_mock(),
            &txaux,
            extra_info,
            &last_account_root_hash,
            create_db(),
            &accounts,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_account_unbond_verify_fail() {
        let db = create_db();
        let (txaux, tx, secret_key, accounts, last_account_root_hash) =
            prepare_app_valid_unbond_tx();
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            unbonding_period: 1,
        };
        let mut mock_bridge = get_enclave_bridge_mock();
        // WrongChainHexId
        {
            let mut extra_info = extra_info.clone();
            extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::WrongChainHexId);
        }
        // AccountNotFound
        {
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &[0; 32],
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::AccountNotFound);
        }
        // AccountIncorrectNonce
        {
            let mut tx = tx.clone();
            tx.nonce = 0;
            let txaux = TxAux::UnbondStakeTx(
                tx.clone(),
                get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
            );
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::AccountIncorrectNonce);
        }
        // ZeroCoin
        {
            let mut tx = tx.clone();
            tx.value = Coin::zero();
            let txaux = TxAux::UnbondStakeTx(
                tx.clone(),
                get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
            );
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::ZeroCoin);
        }
        // InputOutputDoNotMatch
        {
            let mut tx = tx.clone();
            tx.value = (tx.value + Coin::one()).unwrap();
            let txaux = TxAux::UnbondStakeTx(
                tx.clone(),
                get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
            );
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::InputOutputDoNotMatch);
        }
    }

    fn prepare_app_valid_withdraw_tx(
        unbonded_from: Timespec,
    ) -> (
        TxAux,
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
        let account = StakedState::new(1, Coin::zero(), Coin::one(), unbonded_from, addr.into());
        let key = account.key();
        let wrapped = AccountWrapper(account.clone());
        let new_root = tree
            .insert(None, &mut [&key], &mut vec![&wrapped])
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
        let txaux = TxAux::WithdrawUnbondedStakeTx {
            txid: tx.id(),
            no_of_outputs: tx.outputs.len() as TxoIndex,
            witness: witness.clone(),
            payload: TxObfuscated {
                key_from: 0,
                nonce: [0; 12],
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
        let (txaux, _, _, _, _, accounts, last_account_root_hash) =
            prepare_app_valid_withdraw_tx(0);
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            unbonding_period: 1,
        };
        let result = verify(
            &mut get_enclave_bridge_mock(),
            &txaux,
            extra_info,
            &last_account_root_hash,
            create_db(),
            &accounts,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_account_withdraw_verify_fail() {
        let db = create_db();
        let (txaux, tx, _, account, secret_key, accounts, last_account_root_hash) =
            prepare_app_valid_withdraw_tx(0);
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            unbonding_period: 1,
        };
        let mut mock_bridge = get_enclave_bridge_mock();
        // WrongChainHexId
        {
            let mut extra_info = extra_info.clone();
            extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_unbonded_withdraw(&tx, extra_info, account.clone());
            expect_error(&result, Error::WrongChainHexId);
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_unbonded_withdraw(&tx, extra_info, account.clone());
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_unbonded_withdraw(&tx, extra_info, account.clone());
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_unbonded_withdraw(&tx, extra_info, account.clone());
            expect_error(
                &result,
                Error::InvalidSum(CoinError::OutOfBound(Coin::max().into())),
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_unbonded_withdraw(&tx, extra_info, account.clone());
            expect_error(&result, Error::InputOutputDoNotMatch);
        }
        // AccountNotFound
        {
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &[0; 32],
                db.clone(),
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_unbonded_withdraw(&tx, extra_info, account.clone());
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_unbonded_withdraw(&tx, extra_info, account.clone());
            expect_error(&result, Error::AccountWithdrawOutputNotLocked);
        }
        // AccountNotUnbonded
        {
            let (txaux, _, _, account, _, accounts, last_account_root_hash) =
                prepare_app_valid_withdraw_tx(20);
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_unbonded_withdraw(&tx, extra_info, account);
            expect_error(&result, Error::AccountNotUnbonded);
        }
    }

    fn prepare_app_valid_deposit_tx(
        timelocked: bool,
        mock_client: &mut MockClient,
    ) -> (
        Arc<dyn KeyValueDB>,
        TxAux,
        DepositBondTx,
        TxWitness,
        SecretKey,
        AccountStorage,
    ) {
        let (db, txp, _, merkle_tree, secret_key) = prepate_init_tx(timelocked, mock_client);
        let secp = Secp256k1::new();
        let sk2 = SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order");
        let pk2 = PublicKey::from_secret_key(&secp, &sk2);
        let tx = DepositBondTx::new(
            vec![txp],
            RedeemAddress::from(&pk2).into(),
            StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
        );

        let witness: Vec<TxInWitness> =
            vec![get_tx_witness(secp, &tx.id(), &secret_key, &merkle_tree)];
        // TODO: mock enc
        let txaux = TxAux::DepositStakeTx {
            tx: tx.clone(),
            payload: TxObfuscated {
                key_from: 0,
                nonce: [0u8; 12],
                txpayload: PlainTxAux::DepositStakeTx(witness.clone().into()).encode(),
            },
        };
        (
            db,
            txaux,
            tx.clone(),
            witness.into(),
            secret_key,
            AccountStorage::new(Storage::new_db(create_db()), 20).expect("account db"),
        )
    }

    const DEFAULT_CHAIN_ID: u8 = 0;

    #[test]
    fn existing_utxo_input_tx_should_verify() {
        let mut mock_bridge = get_enclave_bridge_mock();
        let (db, txaux, _, _, _, _, accounts) =
            prepare_app_valid_transfer_tx(false, &mut mock_bridge);
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            unbonding_period: 1,
        };
        let last_account_root_hash = [0u8; 32];
        let result = verify(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            db,
            &accounts,
        );
        assert!(result.is_ok());
        let (db, txaux, _, _, _, accounts) = prepare_app_valid_deposit_tx(false, &mut mock_bridge);
        let result = verify(
            &mut mock_bridge,
            &txaux,
            extra_info,
            &last_account_root_hash,
            db,
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

    #[test]
    fn test_deposit_verify_fail() {
        let mut mock_bridge = get_enclave_bridge_mock();
        let (db, txaux, tx, witness, secret_key, accounts) =
            prepare_app_valid_deposit_tx(false, &mut mock_bridge);
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            unbonding_period: 1,
        };
        let last_account_root_hash = [0u8; 32];
        // WrongChainHexId
        {
            let mut extra_info = extra_info.clone();
            extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_bonded_deposit(&tx, &witness, extra_info, vec![], None);
            expect_error(&result, Error::WrongChainHexId);
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_bonded_deposit(&tx, &witness, extra_info, vec![], None);
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_bonded_deposit(&tx, &witness, extra_info, vec![], None);
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_bonded_deposit(&tx, &witness, extra_info, vec![], None);
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_bonded_deposit(&tx, &vec![].into(), extra_info, vec![], None);
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

            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
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
                &MerkleTree::new(vec![RawPubkey::from(
                    PublicKey::from_secret_key(
                        &secp,
                        &SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order"),
                    )
                    .serialize(),
                )]),
            );
            let addr = get_address(&secp, &secret_key).0;
            let input_tx = get_old_tx(addr, false);

            let result = verify_bonded_deposit(
                &tx,
                &witness,
                extra_info,
                vec![TxWithOutputs::Transfer(input_tx)],
                None,
            );
            expect_error(
                &result,
                Error::EcdsaCrypto(secp256k1::Error::InvalidPublicKey),
            );
            let txaux = replace_tx_payload(
                txaux.clone(),
                PlainTxAux::DepositStakeTx(witness.clone()),
                None,
                None,
            );
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
        }
        // InvalidInput
        {
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                create_db(),
                &accounts,
            );
            expect_error(&result, Error::InvalidInput);
        }
        // InputOutputDoNotMatch
        {
            let mut extra_info = extra_info.clone();
            extra_info.min_fee_computed = Fee::new(Coin::one());
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_bonded_deposit(&tx, &witness, extra_info, vec![], None);
            expect_error(&result, Error::InputOutputDoNotMatch);
        }
    }

    fn replace_tx_payload(
        txaux: TxAux,
        plain_tx: PlainTxAux,
        mwitness: Option<StakedStateOpWitness>,
        mtx: Option<DepositBondTx>,
    ) -> TxAux {
        match (txaux, plain_tx.clone()) {
            (
                TxAux::TransferTx {
                    payload:
                        TxObfuscated {
                            key_from, nonce, ..
                        },
                    ..
                },
                PlainTxAux::TransferTx(tx, _),
            ) => TxAux::TransferTx {
                txid: tx.id(),
                inputs: tx.inputs.clone(),
                no_of_outputs: tx.outputs.len() as TxoIndex,
                payload: TxObfuscated {
                    key_from,
                    nonce,
                    txpayload: plain_tx.encode(),
                },
            },
            (
                TxAux::DepositStakeTx {
                    tx,
                    payload:
                        TxObfuscated {
                            key_from, nonce, ..
                        },
                },
                PlainTxAux::DepositStakeTx(_),
            ) => TxAux::DepositStakeTx {
                tx: if let Some(t) = mtx { t } else { tx },
                payload: TxObfuscated {
                    key_from,
                    nonce,
                    txpayload: plain_tx.encode(),
                },
            },
            (
                TxAux::WithdrawUnbondedStakeTx {
                    witness,
                    payload:
                        TxObfuscated {
                            key_from, nonce, ..
                        },
                    ..
                },
                PlainTxAux::WithdrawUnbondedStakeTx(tx),
            ) => TxAux::WithdrawUnbondedStakeTx {
                txid: tx.id(),
                no_of_outputs: tx.outputs.len() as TxoIndex,
                witness: if let Some(w) = mwitness { w } else { witness },
                payload: TxObfuscated {
                    key_from,
                    nonce,
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
            prepare_app_valid_transfer_tx(false, &mut mock_bridge);
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            unbonding_period: 1,
        };
        let last_account_root_hash = [0u8; 32];
        // WrongChainHexId
        {
            let mut extra_info = extra_info.clone();
            extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
            let result = verify_transfer(&tx, &witness, extra_info, vec![]);
            expect_error(&result, Error::WrongChainHexId);
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
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
                Error::InvalidSum(CoinError::OutOfBound(Coin::max().into())),
            );
            let txaux = replace_tx_payload(
                txaux.clone(),
                PlainTxAux::TransferTx(tx, witness),
                None,
                None,
            );
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
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

            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
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
                &MerkleTree::new(vec![RawPubkey::from(
                    PublicKey::from_secret_key(
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
                Error::EcdsaCrypto(secp256k1::Error::InvalidPublicKey),
            );
            let txaux = replace_tx_payload(
                txaux.clone(),
                PlainTxAux::TransferTx(tx.clone(), witness),
                None,
                None,
            );
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
        }
        // InvalidInput
        {
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                create_db(),
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
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
        }
        // OutputInTimelock
        {
            let (db, txaux, tx, witness, _, _, accounts) =
                prepare_app_valid_transfer_tx(true, &mut mock_bridge);
            let addr = get_address(&Secp256k1::new(), &secret_key).0;
            let input_tx = get_old_tx(addr, true);
            let result = verify_transfer(
                &tx,
                &witness,
                extra_info,
                vec![TxWithOutputs::Transfer(input_tx)],
            );
            expect_error(&result, Error::OutputInTimelock);
            let result = verify(
                &mut mock_bridge,
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            assert!(result.is_err());
        }
    }
}
