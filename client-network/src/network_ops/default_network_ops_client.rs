use parity_scale_codec::Decode;
use secstr::SecUtf8;

use chain_core::init::coin::Coin;
use chain_core::state::account::{
    DepositBondTx, StakedState, StakedStateAddress, StakedStateOpAttributes, StakedStateOpWitness,
    UnbondTx, WithdrawUnbondedTx,
};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::fee::FeeAlgorithm;
use chain_core::tx::{TransactionId, TxAux};
use client_common::tendermint::Client;
use client_common::{ErrorKind, Result, ResultExt, SignedTransaction};
use client_core::{Signer, TransactionObfuscation, UnspentTransactions, WalletClient};

use crate::NetworkOpsClient;

/// Default implementation of `NetworkOpsClient`
pub struct DefaultNetworkOpsClient<W, S, C, F, E>
where
    W: WalletClient,
    S: Signer,
    C: Client,
    F: FeeAlgorithm,
    E: TransactionObfuscation,
{
    /// WalletClient
    wallet_client: W,
    signer: S,
    client: C,
    fee_algorithm: F,
    transaction_cipher: E,
}

impl<W, S, C, F, E> DefaultNetworkOpsClient<W, S, C, F, E>
where
    W: WalletClient,
    S: Signer,
    C: Client,
    F: FeeAlgorithm,
    E: TransactionObfuscation,
{
    /// use WalletClient
    pub fn get_wallet(&self) -> &W {
        &self.wallet_client
    }
    /// Creates a new instance of `DefaultNetworkOpsClient`
    pub fn new(
        wallet_client: W,
        signer: S,
        client: C,
        fee_algorithm: F,
        transaction_cipher: E,
    ) -> Self {
        Self {
            wallet_client,
            signer,
            client,
            fee_algorithm,
            transaction_cipher,
        }
    }

    /// Get account info
    fn get_account(&self, staked_state_address: &[u8]) -> Result<StakedState> {
        let bytes = self
            .client
            .query("account", staked_state_address)?
            .bytes()?;

        StakedState::decode(&mut bytes.as_slice()).chain(|| {
            (
                ErrorKind::DeserializationError,
                format!(
                    "Cannot deserialize staked state for address: {}",
                    hex::encode(staked_state_address)
                ),
            )
        })
    }

    /// Get staked state info
    fn get_staked_state_account(
        &self,
        to_staked_account: &StakedStateAddress,
    ) -> Result<StakedState> {
        match to_staked_account {
            StakedStateAddress::BasicRedeem(ref a) => self.get_account(&a.0),
        }
    }
}

impl<W, S, C, F, E> NetworkOpsClient for DefaultNetworkOpsClient<W, S, C, F, E>
where
    W: WalletClient,
    S: Signer,
    C: Client,
    F: FeeAlgorithm,
    E: TransactionObfuscation,
{
    fn create_deposit_bonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        inputs: Vec<TxoPointer>,
        to_address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
    ) -> Result<TxAux> {
        let transaction = DepositBondTx::new(inputs.clone(), to_address, attributes);

        let transactions = inputs
            .into_iter()
            .map(|txo_pointer| {
                let output = self.wallet_client.output(name, passphrase, &txo_pointer)?;
                Ok((txo_pointer, output))
            })
            .collect::<Result<Vec<(TxoPointer, TxOut)>>>()?;
        let unspent_transactions = UnspentTransactions::new(transactions);
        let witness = self.signer.sign(
            name,
            passphrase,
            transaction.id(),
            unspent_transactions.select_all(),
        )?;

        let signed_transaction = SignedTransaction::DepositStakeTransaction(transaction, witness);
        let tx_aux = self.transaction_cipher.encrypt(signed_transaction)?;

        Ok(tx_aux)
    }

    fn create_unbond_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: StakedStateAddress,
        value: Coin,
        attributes: StakedStateOpAttributes,
    ) -> Result<TxAux> {
        let staked_state = self.get_staked_state(name, passphrase, &address)?;
        let nonce = staked_state.nonce;

        let transaction = UnbondTx::new(address, nonce, value, attributes);

        let public_key = match address {
            StakedStateAddress::BasicRedeem(ref redeem_address) => self
                .wallet_client
                .find_staking_key(name, passphrase, redeem_address)?
                .chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        "Address not found in current wallet",
                    )
                })?,
        };
        let private_key = self
            .wallet_client
            .private_key(passphrase, &public_key)?
            .chain(|| {
                (
                    ErrorKind::InvalidInput,
                    "Not able to find private key for given address in current wallet",
                )
            })?;

        let signature = private_key
            .sign(transaction.id())
            .map(StakedStateOpWitness::new)?;

        Ok(TxAux::UnbondStakeTx(transaction, signature))
    }

    fn create_withdraw_unbonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        from_address: &StakedStateAddress,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
    ) -> Result<TxAux> {
        let staked_state = self.get_staked_state(name, passphrase, from_address)?;
        let nonce = staked_state.nonce;

        let transaction = WithdrawUnbondedTx::new(nonce, outputs, attributes);

        let public_key = match from_address {
            StakedStateAddress::BasicRedeem(ref redeem_address) => self
                .wallet_client
                .find_staking_key(name, passphrase, redeem_address)?
                .chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        "Address not found in current wallet",
                    )
                })?,
        };
        let private_key = self
            .wallet_client
            .private_key(passphrase, &public_key)?
            .chain(|| {
                (
                    ErrorKind::InvalidInput,
                    "Not able to find private key for given address in current wallet",
                )
            })?;

        let signature = private_key
            .sign(transaction.id())
            .map(StakedStateOpWitness::new)?;

        let signed_transaction = SignedTransaction::WithdrawUnbondedStakeTransaction(
            transaction,
            staked_state,
            signature,
        );
        let tx_aux = self.transaction_cipher.encrypt(signed_transaction)?;

        Ok(tx_aux)
    }

    fn create_withdraw_all_unbonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        from_address: &StakedStateAddress,
        to_address: ExtendedAddr,
        attributes: TxAttributes,
    ) -> Result<TxAux> {
        let staked_state = self.get_staked_state(name, passphrase, from_address)?;

        let temp_output =
            TxOut::new_with_timelock(to_address.clone(), Coin::zero(), staked_state.unbonded_from);

        let temp_transaction = self.create_withdraw_unbonded_stake_transaction(
            name,
            passphrase,
            from_address,
            vec![temp_output],
            attributes.clone(),
        )?;

        let fee = self
            .fee_algorithm
            .calculate_for_txaux(&temp_transaction)
            .chain(|| {
                (
                    ErrorKind::IllegalInput,
                    "Calculated fee is more than the maximum allowed value",
                )
            })?
            .to_coin();

        let amount = (staked_state.unbonded - fee).chain(|| {
            (
                ErrorKind::IllegalInput,
                "Calculated fee is more than the unbonded amount",
            )
        })?;
        let output = TxOut::new_with_timelock(to_address, amount, staked_state.unbonded_from);

        self.create_withdraw_unbonded_stake_transaction(
            name,
            passphrase,
            from_address,
            vec![output],
            attributes,
        )
    }

    fn get_staked_state(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: &StakedStateAddress,
    ) -> Result<StakedState> {
        // Verify if `address` belongs to current wallet
        match address {
            StakedStateAddress::BasicRedeem(ref redeem_address) => {
                self.wallet_client
                    .find_staking_key(name, passphrase, redeem_address)?;
            }
        }

        self.get_staked_state_account(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use parity_scale_codec::Encode;

    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::CoinError;
    use chain_core::state::account::StakedState;
    use chain_core::tx::data::input::TxoIndex;
    use chain_core::tx::data::TxId;
    use chain_core::tx::fee::Fee;
    use chain_core::tx::{PlainTxAux, TxObfuscated};
    use chain_tx_validation::witness::verify_tx_recover_address;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::*;
    use client_common::{PrivateKey, PublicKey, Transaction};
    use client_core::signer::DefaultSigner;
    use client_core::wallet::DefaultWalletClient;

    #[derive(Debug)]
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
                    Ok(TxAux::DepositStakeTx {
                        tx: tx.clone(),
                        payload: TxObfuscated {
                            txid: tx.id(),
                            key_from: 0,
                            init_vector: [0u8; 12],
                            txpayload: plain.encode(),
                        },
                    })
                }
                SignedTransaction::WithdrawUnbondedStakeTransaction(tx, _, witness) => {
                    let plain = PlainTxAux::WithdrawUnbondedStakeTx(tx.clone());
                    Ok(TxAux::WithdrawUnbondedStakeTx {
                        no_of_outputs: tx.outputs.len() as TxoIndex,
                        witness,
                        payload: TxObfuscated {
                            txid: tx.id(),
                            key_from: 0,
                            init_vector: [0u8; 12],
                            txpayload: plain.encode(),
                        },
                    })
                }
                SignedTransaction::UnbondStakeTransaction(_, _) => unreachable!(),
            }
        }
    }

    #[derive(Debug, Default)]
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
    pub struct MockClient;

    impl Client for MockClient {
        fn genesis(&self) -> Result<Genesis> {
            unreachable!()
        }

        fn status(&self) -> Result<Status> {
            unreachable!()
        }

        fn block(&self, _: u64) -> Result<Block> {
            unreachable!()
        }

        fn block_batch<'a, T: Iterator<Item = &'a u64>>(&self, _heights: T) -> Result<Vec<Block>> {
            unreachable!()
        }

        fn block_results(&self, _height: u64) -> Result<BlockResults> {
            unreachable!()
        }

        fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
            &self,
            _heights: T,
        ) -> Result<Vec<BlockResults>> {
            unreachable!()
        }

        fn broadcast_transaction(&self, _: &[u8]) -> Result<BroadcastTxResult> {
            unreachable!()
        }

        fn query(&self, _path: &str, _data: &[u8]) -> Result<QueryResult> {
            let staked_state = StakedState::new(
                0,
                Coin::zero(),
                Coin::new(2499999999999999999 + 1).unwrap(),
                0,
                StakedStateAddress::BasicRedeem(RedeemAddress::default()),
                None,
            );

            Ok(QueryResult {
                response: Response {
                    code: 0,
                    value: base64::encode(&staked_state.encode()),
                    log: "".to_owned(),
                },
            })
        }
    }

    #[test]
    fn check_create_deposit_bonded_stake_transaction() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        wallet_client.new_wallet(name, passphrase).unwrap();

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        let inputs: Vec<TxoPointer> = vec![];
        let to_staked_account = network_ops_client
            .get_wallet()
            .new_staking_address(name, passphrase)
            .unwrap();;

        let attributes = StakedStateOpAttributes::new(0);
        assert!(network_ops_client
            .create_deposit_bonded_stake_transaction(
                name,
                passphrase,
                inputs,
                to_staked_account,
                attributes,
            )
            .is_ok());
    }

    #[test]
    fn check_create_unbond_stake_transaction() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        wallet_client.new_wallet(name, passphrase).unwrap();

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        let value = Coin::new(0).unwrap();
        let address = network_ops_client
            .get_wallet()
            .new_staking_address(name, passphrase)
            .unwrap();
        let attributes = StakedStateOpAttributes::new(0);

        assert!(network_ops_client
            .create_unbond_stake_transaction(name, passphrase, address, value, attributes)
            .is_ok());
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        network_ops_client
            .get_wallet()
            .new_wallet(name, passphrase)
            .unwrap();

        let from_address = network_ops_client
            .get_wallet()
            .new_staking_address(name, passphrase)
            .unwrap();

        let transaction = network_ops_client
            .create_withdraw_unbonded_stake_transaction(
                name,
                passphrase,
                &from_address,
                Vec::new(),
                TxAttributes::new(171),
            )
            .unwrap();

        match transaction {
            TxAux::WithdrawUnbondedStakeTx {
                payload: TxObfuscated { txid, .. },
                witness,
                ..
            } => {
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
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        network_ops_client
            .get_wallet()
            .new_wallet(name, passphrase)
            .unwrap();

        let from_address = network_ops_client
            .get_wallet()
            .new_staking_address(name, passphrase)
            .unwrap();
        let to_address = ExtendedAddr::OrTree([0; 32]);

        let transaction = network_ops_client
            .create_withdraw_all_unbonded_stake_transaction(
                name,
                passphrase,
                &from_address,
                to_address,
                TxAttributes::new(171),
            )
            .unwrap();

        match transaction {
            TxAux::WithdrawUnbondedStakeTx {
                witness,
                payload: TxObfuscated {
                    txid, txpayload, ..
                },
                ..
            } => {
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
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        network_ops_client
            .get_wallet()
            .new_wallet(name, passphrase)
            .unwrap();

        assert_eq!(
            ErrorKind::InvalidInput,
            network_ops_client
                .create_withdraw_unbonded_stake_transaction(
                    name,
                    passphrase,
                    &StakedStateAddress::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                        &PrivateKey::new().unwrap()
                    ))),
                    Vec::new(),
                    TxAttributes::new(171),
                )
                .unwrap_err()
                .kind()
        );
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction_wallet_not_found() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());
        let tendermint_client = MockClient::default();

        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            signer,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        assert_eq!(
            ErrorKind::InvalidInput,
            network_ops_client
                .create_withdraw_unbonded_stake_transaction(
                    name,
                    passphrase,
                    &StakedStateAddress::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                        &PrivateKey::new().unwrap()
                    ))),
                    Vec::new(),
                    TxAttributes::new(171),
                )
                .unwrap_err()
                .kind()
        );
    }
}
