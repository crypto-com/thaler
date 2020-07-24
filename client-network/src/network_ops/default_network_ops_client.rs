use parity_scale_codec::Decode;

use crate::NetworkOpsClient;
use chain_core::common::Timespec;
use chain_core::init::coin::{sum_coins, Coin};
use chain_core::state::account::{
    CouncilNodeMeta, DepositBondTx, NodeMetadata, StakedState, StakedStateAddress,
    StakedStateOpAttributes, StakedStateOpWitness, UnbondTx, UnjailTx, WithdrawUnbondedTx,
};
use chain_core::state::validator::NodeJoinRequestTx;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::fee::FeeAlgorithm;
use chain_core::tx::{TxAux, TxPublicAux};
use chain_storage::jellyfish::SparseMerkleProof;
use chain_tx_validation::{check_inputs_basic, check_outputs_basic, verify_unjailed};
use client_common::tendermint::types::{AbciQueryExt, Genesis, StatusResponse};
use client_common::tendermint::Client;
use client_common::{
    Error, ErrorKind, Result, ResultExt, SecKey, SignedTransaction, Storage, Transaction,
    TransactionObfuscation,
};
use client_core::signer::{DummySigner, Signer, WalletSignerManager};
use client_core::transaction_builder::WitnessedUTxO;
use client_core::types::TransactionPending;
use client_core::{UnspentTransactions, WalletClient};
use tendermint::{block::Height, Time};

/// Default implementation of `NetworkOpsClient`
#[derive(Clone)]
pub struct DefaultNetworkOpsClient<W, S, C, F, E>
where
    W: WalletClient,
    S: Storage,
    C: Client,
    F: FeeAlgorithm,
    E: TransactionObfuscation,
{
    wallet_client: W,
    signer_manager: WalletSignerManager<S>,
    client: C,
    fee_algorithm: F,
    transaction_cipher: E,
}

impl<W, S, C, F, E> DefaultNetworkOpsClient<W, S, C, F, E>
where
    W: WalletClient,
    S: Storage,
    C: Client,
    F: FeeAlgorithm,
    E: TransactionObfuscation,
{
    /// Creates a new instance of `DefaultNetworkOpsClient`
    pub fn new(
        wallet_client: W,
        signer_manager: WalletSignerManager<S>,
        client: C,
        fee_algorithm: F,
        transaction_cipher: E,
    ) -> Self {
        Self {
            wallet_client,
            signer_manager,
            client,
            fee_algorithm,
            transaction_cipher,
        }
    }

    /// Returns current underlying wallet client
    pub fn get_wallet_client(&self) -> &W {
        &self.wallet_client
    }

    /// Calculate the withdraw unbounded fee
    fn calculate_fee(&self, outputs: Vec<TxOut>, attributes: TxAttributes) -> Result<Coin> {
        let tx = WithdrawUnbondedTx::new(0, outputs, attributes);
        // mock the signature
        let dummy_signer = DummySigner();
        let tx_aux = dummy_signer.mock_txaux_for_withdraw(tx);
        let fee = self
            .fee_algorithm
            .calculate_for_txaux(&tx_aux)
            .chain(|| {
                (
                    ErrorKind::IllegalInput,
                    "Calculated fee is more than the maximum allowed value",
                )
            })?
            .to_coin();
        Ok(fee)
    }

    fn get_last_block_time(&self) -> Result<Timespec> {
        let status = self.client.status()?;
        Ok(to_timespec(
            if status.sync_info.latest_block_height == Height(0) {
                self.client.genesis()?.genesis_time
            } else {
                status.sync_info.latest_block_time
            },
        ))
    }
}

impl<W, S, C, F, E> NetworkOpsClient for DefaultNetworkOpsClient<W, S, C, F, E>
where
    W: WalletClient,
    S: Storage + 'static,
    C: Client,
    F: FeeAlgorithm,
    E: TransactionObfuscation,
{
    fn calculate_deposit_fee(&self) -> Result<Coin> {
        let dummy_signer = DummySigner();
        let tx_aux = dummy_signer
            .mock_txaux_for_deposit(&[WitnessedUTxO::dummy()])
            .chain(|| (ErrorKind::ValidationError, "Calculated fee failed"))?;
        let fee = self
            .fee_algorithm
            .calculate_for_txaux(&tx_aux)
            .chain(|| {
                (
                    ErrorKind::IllegalInput,
                    "Calculated fee is more than the maximum allowed value",
                )
            })?
            .to_coin();
        Ok(fee)
    }

    fn create_deposit_bonded_stake_transaction<'a>(
        &'a self,
        name: &'a str,
        enckey: &'a SecKey,
        transactions: Vec<(TxoPointer, TxOut)>,
        to_address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
        verify_staking: bool,
    ) -> Result<(TxAux, TransactionPending)> {
        if let Some(staking) = self.get_staking(name, &to_address, verify_staking)? {
            verify_unjailed(&staking).map_err(|e| {
                Error::new(
                    ErrorKind::ValidationError,
                    format!("Failed to validate staking account: {}", e),
                )
            })?;
        }
        let inputs = transactions
            .iter()
            .map(|(input, _)| input.clone())
            .collect::<Vec<_>>();

        let transaction = DepositBondTx::new(inputs.clone(), to_address, attributes);
        let unspent_transactions = UnspentTransactions::new(transactions);
        let signer =
            self.signer_manager
                .create_signer(name, enckey, &self.signer_manager.hw_key_service);

        let tx = Transaction::DepositStakeTransaction(transaction.clone());
        let witness = signer.schnorr_sign_transaction(&tx, &unspent_transactions.select_all())?;

        check_inputs_basic(&transaction.inputs, &witness).map_err(|e| {
            Error::new(
                ErrorKind::ValidationError,
                format!("Failed to validate deposit transaction inputs: {}", e),
            )
        })?;

        let signed_transaction = SignedTransaction::DepositStakeTransaction(transaction, witness);
        let tx_aux = self.transaction_cipher.encrypt(signed_transaction)?;
        let block_height = match self.wallet_client.get_current_block_height() {
            Ok(h) => h,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => 0, // to make unit test pass
            Err(e) => return Err(e),
        };
        let pending_transaction = TransactionPending {
            block_height,
            used_inputs: inputs,
            return_amount: Coin::zero(),
        };
        Ok((tx_aux, pending_transaction))
    }

    fn create_unbond_stake_transaction(
        &self,
        name: &str,
        enckey: &SecKey,
        address: StakedStateAddress,
        value: Coin,
        attributes: StakedStateOpAttributes,
        verify_staking: bool,
    ) -> Result<TxAux> {
        let staked_state = self.get_staked_state(name, &address, verify_staking)?;

        verify_unjailed(&staked_state).map_err(|e| {
            Error::new(
                ErrorKind::ValidationError,
                format!("Failed to validate staking account: {}", e),
            )
        })?;

        let nonce = staked_state.nonce;

        let transaction = UnbondTx::new(address, nonce, value, attributes);
        let tx = Transaction::UnbondStakeTransaction(transaction.clone());

        let public_key = match address {
            StakedStateAddress::BasicRedeem(ref redeem_address) => self
                .wallet_client
                .find_staking_key(name, enckey, redeem_address)?
                .chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        "Address not found in current wallet",
                    )
                })?,
        };
        let sign_key = self.wallet_client.sign_key(name, enckey, &public_key)?;

        let signature = sign_key.sign(&tx).map(StakedStateOpWitness::new)?;

        let txaux = TxAux::PublicTx(TxPublicAux::UnbondStakeTx(transaction, signature));

        let fee = self
            .fee_algorithm
            .calculate_for_txaux(&txaux)
            .chain(|| {
                (
                    ErrorKind::IllegalInput,
                    "Calculated fee is more than the maximum allowed value",
                )
            })?
            .to_coin();
        if staked_state.bonded < (value + fee).unwrap() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Staking account does not have enough coins to unbond (synchronizing your wallet may help)",
            ));
        }

        Ok(txaux)
    }

    fn create_withdraw_unbonded_stake_transaction(
        &self,
        name: &str,
        enckey: &SecKey,
        from_address: &StakedStateAddress,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        verify_staking: bool,
    ) -> Result<(TxAux, TransactionPending)> {
        let last_block_time = self.get_last_block_time()?;
        let staked_state = self.get_staked_state(name, from_address, verify_staking)?;
        if staked_state.unbonded_from > last_block_time {
            let seconds = staked_state.unbonded_from - last_block_time;
            let duration = std::time::Duration::from_secs(seconds);
            return Err(Error::new(
                ErrorKind::ValidationError,
                format!(
                    "Staking state is not yet unbonded, time left: {:?}",
                    duration
                ),
            ));
        }

        verify_unjailed(&staked_state).map_err(|e| {
            Error::new(
                ErrorKind::ValidationError,
                format!("Failed to validate staking account: {}", e),
            )
        })?;

        let output_value = sum_coins(outputs.iter().map(|output| output.value))
            .chain(|| (ErrorKind::InvalidInput, "Error while adding output values"))?;

        if staked_state.unbonded < output_value {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Staking account does not have enough unbonded coins to withdraw (synchronizing your wallet may help)",
            ));
        }

        let nonce = staked_state.nonce;

        let transaction = WithdrawUnbondedTx::new(nonce, outputs, attributes);
        let tx = Transaction::WithdrawUnbondedStakeTransaction(transaction.clone());

        let public_key = match from_address {
            StakedStateAddress::BasicRedeem(ref redeem_address) => self
                .wallet_client
                .find_staking_key(name, enckey, redeem_address)?
                .chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        "Address not found in current wallet",
                    )
                })?,
        };
        let sign_key = self.wallet_client.sign_key(name, enckey, &public_key)?;
        let signature = sign_key.sign(&tx).map(StakedStateOpWitness::new)?;

        let signed_transaction =
            SignedTransaction::WithdrawUnbondedStakeTransaction(transaction, signature);
        let tx_aux = self.transaction_cipher.encrypt(signed_transaction)?;
        let block_height = match self.wallet_client.get_current_block_height() {
            Ok(h) => h,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => 0, // to make unit test pass
            Err(e) => return Err(e),
        };
        let pending_transaction = TransactionPending {
            block_height,
            used_inputs: vec![],
            return_amount: output_value,
        };
        Ok((tx_aux, pending_transaction))
    }

    fn create_unjail_transaction(
        &self,
        name: &str,
        enckey: &SecKey,
        address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
        verify_staking: bool,
    ) -> Result<TxAux> {
        let staked_state = self.get_staked_state(name, &address, verify_staking)?;

        if !staked_state.is_jailed() {
            return Err(Error::new(
                ErrorKind::IllegalInput,
                "You can only unjail an already jailed account (synchronizing your wallet may help)",
            ));
        }

        let nonce = staked_state.nonce;

        let transaction = UnjailTx {
            nonce,
            address,
            attributes,
        };
        let tx = Transaction::UnjailTransaction(transaction.clone());

        let public_key = match address {
            StakedStateAddress::BasicRedeem(ref redeem_address) => self
                .wallet_client
                .find_staking_key(name, enckey, redeem_address)?
                .chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        "Address not found in current wallet",
                    )
                })?,
        };
        let sign_key = self.wallet_client.sign_key(name, enckey, &public_key)?;
        let signature = sign_key.sign(&tx).map(StakedStateOpWitness::new)?;

        Ok(TxAux::PublicTx(TxPublicAux::UnjailTx(
            transaction,
            signature,
        )))
    }

    fn create_withdraw_all_unbonded_stake_transaction(
        &self,
        name: &str,
        enckey: &SecKey,
        from_address: &StakedStateAddress,
        to_address: ExtendedAddr,
        attributes: TxAttributes,
        verify_staking: bool,
    ) -> Result<(TxAux, TransactionPending)> {
        let staked_state = self.get_staked_state(name, from_address, verify_staking)?;

        verify_unjailed(&staked_state).map_err(|e| {
            Error::new(
                ErrorKind::ValidationError,
                format!("Failed to validate staking account: {}", e),
            )
        })?;

        let temp_output =
            TxOut::new_with_timelock(to_address.clone(), Coin::zero(), staked_state.unbonded_from);
        let fee = self.calculate_fee(vec![temp_output], attributes.clone())?;
        let amount = (staked_state.unbonded - fee).chain(|| {
            (
                ErrorKind::IllegalInput,
                "Calculated fee is more than the unbonded amount",
            )
        })?;
        let outputs = vec![TxOut::new_with_timelock(
            to_address,
            amount,
            staked_state.unbonded_from,
        )];

        check_outputs_basic(&outputs).map_err(|e| {
            Error::new(
                ErrorKind::ValidationError,
                format!("Failed to validate staking account: {}", e),
            )
        })?;

        self.create_withdraw_unbonded_stake_transaction(
            name,
            enckey,
            from_address,
            outputs,
            attributes,
            verify_staking,
        )
    }

    fn create_node_join_transaction(
        &self,
        name: &str,
        enckey: &SecKey,
        staking_account_address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
        node_metadata: CouncilNodeMeta,
        verify_staking: bool,
    ) -> Result<TxAux> {
        let staked_state = self.get_staked_state(name, &staking_account_address, verify_staking)?;

        verify_unjailed(&staked_state).map_err(|e| {
            Error::new(
                ErrorKind::ValidationError,
                format!("Failed to validate staking account: {}", e),
            )
        })?;

        let transaction = NodeJoinRequestTx {
            nonce: staked_state.nonce,
            address: staking_account_address,
            attributes,
            node_meta: NodeMetadata::CouncilNode(node_metadata),
        };
        let tx = Transaction::NodejoinTransaction(transaction.clone());

        let public_key = match staking_account_address {
            StakedStateAddress::BasicRedeem(ref redeem_address) => self
                .wallet_client
                .find_staking_key(name, enckey, redeem_address)?
                .chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        "Address not found in current wallet",
                    )
                })?,
        };
        let sign_key = self.wallet_client.sign_key(name, enckey, &public_key)?;
        let signature = sign_key.sign(&tx).map(StakedStateOpWitness::new)?;

        Ok(TxAux::PublicTx(TxPublicAux::NodeJoinTx(
            transaction,
            signature,
        )))
    }

    fn get_staking(
        &self,
        name: &str,
        address: &StakedStateAddress,
        verify: bool,
    ) -> Result<Option<StakedState>> {
        let mstaking = if verify {
            let sync_state = self.wallet_client.get_sync_state(name)?;
            let rsp = self.client.query(
                "staking",
                address.as_ref(),
                Some(sync_state.last_block_height.into()),
                true,
            )?;
            let mstaking = <Option<StakedState>>::decode(&mut rsp.bytes().as_slice())
                .err_kind(ErrorKind::DeserializationError, || {
                    format!("Cannot deserialize staked state for address: {}", address)
                })?;

            let mbytes = if let Some(proof) = rsp.proof.as_ref() {
                if let Some(evidence) = proof.ops.first() {
                    Some(evidence.data.as_slice())
                } else {
                    None
                }
            } else {
                None
            };
            let mut proof_bytes = mbytes.err_kind(ErrorKind::TendermintRpcError, || {
                format!("There is no proof for address: {}", address)
            })?;
            let proof = SparseMerkleProof::decode(&mut proof_bytes).err_kind(
                ErrorKind::DeserializationError,
                || {
                    format!(
                        "Cannot deserialize staked state proof for address: {}",
                        address
                    )
                },
            )?;

            proof
                .verify(sync_state.staking_root, address, mstaking.as_ref())
                .err_kind(ErrorKind::VerifyError, || "Verify staking state failed")?;

            mstaking
        } else {
            let bytes = self
                .client
                .query("staking", address.as_ref(), None, false)?
                .bytes();
            <Option<StakedState>>::decode(&mut bytes.as_slice())
                .err_kind(ErrorKind::DeserializationError, || {
                    format!("Cannot deserialize staked state for address: {}", address)
                })?
        };
        Ok(mstaking)
    }

    fn get_genesis(&self) -> Result<Genesis> {
        self.client.genesis()
    }

    fn get_status(&self) -> Result<StatusResponse> {
        self.client.status()
    }
}

fn to_timespec(time: Time) -> Timespec {
    time.duration_since(Time::unix_epoch()).unwrap().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secstr::SecUtf8;

    use parity_scale_codec::Encode;

    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::CoinError;
    use chain_core::state::account::{StakedState, StakedStateOpAttributes, Validator};
    use chain_core::state::tendermint::BlockHeight;
    use chain_core::state::tendermint::TendermintValidatorPubKey;
    use chain_core::state::ChainState;
    use chain_core::tx::data::input::TxoSize;
    use chain_core::tx::data::TxId;
    use chain_core::tx::fee::Fee;
    use chain_core::tx::TransactionId;
    use chain_core::tx::{PlainTxAux, TxEnclaveAux, TxObfuscated};
    use chain_tx_validation::witness::verify_tx_recover_address;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::mock;
    use client_common::tendermint::types::*;
    use client_common::{seckey::derive_enckey, PrivateKey, PublicKey, Transaction};
    use client_core::service::HwKeyService;
    use client_core::signer::WalletSignerManager;
    use client_core::types::WalletKind;
    use client_core::wallet::DefaultWalletClient;
    use test_common::chain_env::mock_confidential_init;

    #[derive(Debug, Clone)]
    struct MockTransactionCipher;

    impl TransactionObfuscation for MockTransactionCipher {
        fn decrypt(
            &self,
            _transaction_ids: &[TxId],
            _private_key: &PrivateKey,
        ) -> Result<Vec<Transaction>> {
            unreachable!()
        }

        fn encrypt(&self, transaction: SignedTransaction) -> Result<TxAux> {
            match transaction {
                SignedTransaction::TransferTransaction(_, _) => unreachable!(),
                SignedTransaction::DepositStakeTransaction(tx, witness) => {
                    let plain = PlainTxAux::DepositStakeTx(witness);
                    Ok(TxAux::EnclaveTx(TxEnclaveAux::DepositStakeTx {
                        tx: tx.clone(),
                        payload: TxObfuscated {
                            txid: tx.id(),
                            key_from: BlockHeight::genesis(),
                            init_vector: [0u8; 12],
                            txpayload: plain.encode(),
                        },
                    }))
                }
                SignedTransaction::WithdrawUnbondedStakeTransaction(tx, witness) => {
                    let plain = PlainTxAux::WithdrawUnbondedStakeTx(tx.clone());
                    Ok(TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx {
                        no_of_outputs: tx.outputs.len() as TxoSize,
                        witness,
                        payload: TxObfuscated {
                            txid: tx.id(),
                            key_from: BlockHeight::genesis(),
                            init_vector: [0u8; 12],
                            txpayload: plain.encode(),
                        },
                    }))
                }
            }
        }
    }

    #[derive(Debug, Clone, Default)]
    struct UnitFeeAlgorithm;

    impl FeeAlgorithm for UnitFeeAlgorithm {
        fn calculate_fee(&self, _num_bytes: usize) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::unit()))
        }

        fn calculate_for_txaux(&self, _txaux: &TxAux) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::unit()))
        }
    }

    #[derive(Default, Clone)]
    pub struct MockJailedClient;

    impl Client for MockJailedClient {
        fn genesis(&self) -> Result<Genesis> {
            unreachable!()
        }

        fn status(&self) -> Result<StatusResponse> {
            unreachable!()
        }

        fn block(&self, _: u64) -> Result<Block> {
            unreachable!()
        }

        fn block_batch<'a, T: Iterator<Item = &'a u64>>(&self, _heights: T) -> Result<Vec<Block>> {
            unreachable!()
        }

        fn block_results(&self, _height: u64) -> Result<BlockResultsResponse> {
            unreachable!()
        }

        fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
            &self,
            _heights: T,
        ) -> Result<Vec<BlockResultsResponse>> {
            unreachable!()
        }

        fn broadcast_transaction(&self, _: &[u8]) -> Result<BroadcastTxResponse> {
            unreachable!()
        }

        fn query(
            &self,
            _path: &str,
            _data: &[u8],
            _height: Option<Height>,
            _prove: bool,
        ) -> Result<AbciQuery> {
            let staked_state = StakedState::new(
                0,
                Coin::new(1000000).unwrap(),
                Coin::new(2499999999999999999 + 1).unwrap(),
                0,
                StakedStateAddress::BasicRedeem(RedeemAddress::default()),
                Some(Validator {
                    council_node: CouncilNodeMeta::new(
                        TendermintValidatorPubKey::Ed25519([0xcd; 32]),
                        mock_confidential_init(),
                    ),
                    jailed_until: Some(100),
                    inactive_time: Some(0),
                    inactive_block: Some(BlockHeight::genesis()),
                    used_validator_addresses: vec![],
                }),
            );

            Ok(AbciQuery {
                value: Some(staked_state).encode(),
                ..Default::default()
            })
        }

        fn query_state_batch<T: Iterator<Item = u64>>(
            &self,
            _heights: T,
        ) -> Result<Vec<ChainState>> {
            unreachable!()
        }
    }

    #[derive(Default, Clone)]
    pub struct MockClient;

    impl Client for MockClient {
        fn genesis(&self) -> Result<Genesis> {
            unreachable!()
        }

        fn status(&self) -> Result<StatusResponse> {
            Ok(StatusResponse {
                sync_info: status::SyncInfo {
                    latest_block_height: Height::default(),
                    latest_app_hash: None,
                    ..mock::sync_info()
                },
                ..mock::status_response()
            })
        }

        fn block(&self, _: u64) -> Result<Block> {
            unreachable!()
        }

        fn block_batch<'a, T: Iterator<Item = &'a u64>>(&self, _heights: T) -> Result<Vec<Block>> {
            unreachable!()
        }

        fn block_results(&self, _height: u64) -> Result<BlockResultsResponse> {
            unreachable!()
        }

        fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
            &self,
            _heights: T,
        ) -> Result<Vec<BlockResultsResponse>> {
            unreachable!()
        }

        fn broadcast_transaction(&self, _: &[u8]) -> Result<BroadcastTxResponse> {
            unreachable!()
        }

        fn query(
            &self,
            _path: &str,
            _data: &[u8],
            _height: Option<Height>,
            _prove: bool,
        ) -> Result<AbciQuery> {
            let staked_state = StakedState::new(
                0,
                Coin::new(1000000).unwrap(),
                Coin::new(2499999999999999999 + 1).unwrap(),
                0,
                StakedStateAddress::BasicRedeem(RedeemAddress::default()),
                None,
            );

            Ok(AbciQuery {
                value: Some(staked_state).encode(),
                ..Default::default()
            })
        }

        fn query_state_batch<T: Iterator<Item = u64>>(
            &self,
            _heights: T,
        ) -> Result<Vec<ChainState>> {
            unreachable!()
        }
    }

    #[test]
    fn check_create_deposit_bonded_stake_transaction() {
        let name = "name";
        let passphrase = SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer_manager = WalletSignerManager::new(storage.clone(), HwKeyService::default());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let input = TxoPointer::new([0; 32], 0);
        let output = TxOut {
            address: ExtendedAddr::OrTree([0; 32]),
            value: Coin::new(10).unwrap(),
            valid_from: None,
        };
        let transactions = vec![(input, output)];

        let (enckey, _) = wallet_client
            .new_wallet(name, &passphrase, WalletKind::Basic, None)
            .unwrap();

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer_manager,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        let to_staked_account = network_ops_client
            .get_wallet_client()
            .new_staking_address(name, &enckey)
            .unwrap();

        let attributes = StakedStateOpAttributes::new(0);

        assert_eq!(
            ErrorKind::InvalidInput,
            network_ops_client
                .create_deposit_bonded_stake_transaction(
                    name,
                    &enckey,
                    transactions,
                    to_staked_account,
                    attributes,
                    false
                )
                .unwrap_err()
                .kind()
        );
    }

    #[test]
    fn check_create_unbond_stake_transaction() {
        let name = "name";
        let passphrase = SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer_manager = WalletSignerManager::new(storage.clone(), HwKeyService::default());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let (enckey, _) = wallet_client
            .new_wallet(name, &passphrase, WalletKind::Basic, None)
            .unwrap();

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer_manager,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        let value = Coin::new(0).unwrap();
        let address = network_ops_client
            .get_wallet_client()
            .new_staking_address(name, &enckey)
            .unwrap();
        let attributes = StakedStateOpAttributes::new(0);

        assert!(network_ops_client
            .create_unbond_stake_transaction(name, &enckey, address, value, attributes, false)
            .is_ok());
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction() {
        let name = "name";
        let passphrase = SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer_manager = WalletSignerManager::new(storage.clone(), HwKeyService::default());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer_manager,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        let (enckey, _) = network_ops_client
            .get_wallet_client()
            .new_wallet(name, &passphrase, WalletKind::Basic, None)
            .unwrap();

        let from_address = network_ops_client
            .get_wallet_client()
            .new_staking_address(name, &enckey)
            .unwrap();

        let (transaction, _pending_tx) = network_ops_client
            .create_withdraw_unbonded_stake_transaction(
                name,
                &enckey,
                &from_address,
                vec![TxOut::new(ExtendedAddr::OrTree([0; 32]), Coin::unit())],
                TxAttributes::new(171),
                false,
            )
            .unwrap();

        match transaction {
            TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx {
                payload: TxObfuscated { txid, .. },
                witness,
                ..
            }) => {
                let account_address = verify_tx_recover_address(&witness, &txid)
                    .expect("Unable to verify transaction");

                assert_eq!(account_address, from_address)
            }
            _ => unreachable!(
                "`create_withdraw_unbonded_stake_transaction()` created invalid transaction type"
            ),
        }
    }

    #[test]
    fn check_withdraw_all_unbonded_stake_transaction() {
        let name = "name";
        let passphrase = SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer_manager = WalletSignerManager::new(storage.clone(), HwKeyService::default());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer_manager,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        let (enckey, _) = network_ops_client
            .get_wallet_client()
            .new_wallet(name, &passphrase, WalletKind::Basic, None)
            .unwrap();

        let from_address = network_ops_client
            .get_wallet_client()
            .new_staking_address(name, &enckey)
            .unwrap();
        let to_address = ExtendedAddr::OrTree([0; 32]);

        let (transaction, _) = network_ops_client
            .create_withdraw_all_unbonded_stake_transaction(
                name,
                &enckey,
                &from_address,
                to_address,
                TxAttributes::new(171),
                false,
            )
            .unwrap();

        match transaction {
            TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx {
                witness,
                payload: TxObfuscated {
                    txid, txpayload, ..
                },
                ..
            }) => {
                let account_address = verify_tx_recover_address(&witness, &txid)
                    .expect("Unable to verify transaction");

                assert_eq!(account_address, from_address);

                // NOTE: Mock decryption based on encryption logic in `MockTransactionCipher`
                let tx = PlainTxAux::decode(&mut txpayload.as_slice());
                if let Ok(PlainTxAux::WithdrawUnbondedStakeTx(transaction)) = tx {
                    let amount = transaction.outputs[0].value;
                    assert_eq!(amount, Coin::new(2500000000000000000 - 1).unwrap());
                }
            }
            _ => unreachable!(
                "`create_withdraw_unbonded_stake_transaction()` created invalid transaction type"
            ),
        }
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction_address_not_found() {
        let name = "name";
        let passphrase = SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer_manager = WalletSignerManager::new(storage.clone(), HwKeyService::default());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer_manager,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        let (enckey, _) = network_ops_client
            .get_wallet_client()
            .new_wallet(name, &passphrase, WalletKind::Basic, None)
            .unwrap();

        assert_eq!(
            ErrorKind::InvalidInput,
            network_ops_client
                .create_withdraw_unbonded_stake_transaction(
                    name,
                    &enckey,
                    &StakedStateAddress::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                        &PrivateKey::new().unwrap()
                    ))),
                    vec![TxOut::new(ExtendedAddr::OrTree([0; 32]), Coin::unit())],
                    TxAttributes::new(171),
                    false
                )
                .unwrap_err()
                .kind()
        );
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction_wallet_not_found() {
        let name = "name";
        let enckey = &derive_enckey(&SecUtf8::from("passphrase"), name).unwrap();

        let storage = MemoryStorage::default();
        let signer_manager = WalletSignerManager::new(storage.clone(), HwKeyService::default());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());
        let tendermint_client = MockClient::default();

        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer_manager,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            network_ops_client
                .create_withdraw_unbonded_stake_transaction(
                    name,
                    enckey,
                    &StakedStateAddress::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                        &PrivateKey::new().unwrap()
                    ))),
                    Vec::new(),
                    TxAttributes::new(171),
                    false
                )
                .unwrap_err()
                .kind()
        );
    }

    #[test]
    fn check_unjail_transaction() {
        let name = "name";
        let passphrase = SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer_manager = WalletSignerManager::new(storage.clone(), HwKeyService::default());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let tendermint_client = MockJailedClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer_manager,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        let (enckey, _) = network_ops_client
            .get_wallet_client()
            .new_wallet(name, &passphrase, WalletKind::Basic, None)
            .unwrap();

        let from_address = network_ops_client
            .get_wallet_client()
            .new_staking_address(name, &enckey)
            .unwrap();

        let transaction = network_ops_client
            .create_unjail_transaction(
                name,
                &enckey,
                from_address,
                StakedStateOpAttributes::new(171),
                false,
            )
            .unwrap();
        match transaction {
            TxAux::PublicTx(TxPublicAux::UnjailTx(tx, witness)) => {
                let txid = tx.id();
                let account_address = verify_tx_recover_address(&witness, &txid)
                    .expect("Unable to verify transaction");
                assert_eq!(account_address, from_address);
            }
            _ => unreachable!("`unjail_tx()` created invalid transaction"),
        }
    }

    #[test]
    fn check_node_join_transaction() {
        let name = "name";
        let passphrase = SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer_manager = WalletSignerManager::new(storage.clone(), HwKeyService::default());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer_manager,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        let (enckey, _) = network_ops_client
            .get_wallet_client()
            .new_wallet(name, &passphrase, WalletKind::Basic, None)
            .unwrap();

        let staking_account_address = network_ops_client
            .get_wallet_client()
            .new_staking_address(name, &enckey)
            .unwrap();

        let mut validator_pubkey = [0; 32];
        validator_pubkey.copy_from_slice(
            &base64::decode("P2B49bRtePqHr0JGRVAOS9ZqSFjBpS6dFtCah9p+cro=").unwrap(),
        );

        let node_metadata = CouncilNodeMeta::new_with_details(
            "test".to_owned(),
            None,
            TendermintValidatorPubKey::Ed25519(validator_pubkey),
            mock_confidential_init(),
        );

        let transaction = network_ops_client
            .create_node_join_transaction(
                name,
                &enckey,
                staking_account_address,
                StakedStateOpAttributes::new(171),
                node_metadata,
                false,
            )
            .unwrap();

        match transaction {
            TxAux::PublicTx(TxPublicAux::NodeJoinTx(tx, witness)) => {
                let txid = tx.id();
                let account_address = verify_tx_recover_address(&witness, &txid)
                    .expect("Unable to verify transaction");
                assert_eq!(account_address, staking_account_address);
            }
            _ => unreachable!("`create_node_join_tx()` created invalid transaction"),
        }
    }
}
