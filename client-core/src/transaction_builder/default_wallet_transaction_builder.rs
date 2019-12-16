use secstr::SecUtf8;

use chain_core::init::coin::{sum_coins, Coin};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::fee::FeeAlgorithm;
use chain_core::tx::TxAux;
use client_common::{ErrorKind, Result, ResultExt, SignedTransaction, Storage};

use crate::signer::WalletSignerManager;
use crate::transaction_builder::RawTransferTransactionBuilder;
use crate::{
    SelectedUnspentTransactions, TransactionObfuscation, UnspentTransactions,
    WalletTransactionBuilder,
};

/// Default implementation of `TransactionBuilder`
///
/// # Algorithm
///
/// 1. Calculate `output_value`: Sum of all the output values.
/// 2. Initialize `fees = 0`.
/// 3. Select unspent transactions with `fees + output_value`.
/// 4. Build transaction with selected unspent transactions (also add an extra output for change amount).
/// 5. Sign transaction with dummy signer.
/// 6. Wrap up transaction.
/// 7. Calculate `new_fees`.
/// 8. If `new_fees > fees`, then change `fees = new_fees` and goto step 3, otherwise return signed transaction.
///
#[derive(Debug)]
pub struct DefaultWalletTransactionBuilder<S, F, O>
where
    S: Storage,
    F: FeeAlgorithm + Clone,
    O: TransactionObfuscation,
{
    signer_manager: WalletSignerManager<S>,
    fee_algorithm: F,
    transaction_obfuscation: O,
}

impl<S, F, O> WalletTransactionBuilder for DefaultWalletTransactionBuilder<S, F, O>
where
    S: Storage,
    F: FeeAlgorithm + Clone,
    O: TransactionObfuscation,
{
    fn build_transfer_tx(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        unspent_transactions: UnspentTransactions,
        outputs: Vec<TxOut>,
        return_address: ExtendedAddr,
        attributes: TxAttributes,
    ) -> Result<TxAux> {
        let mut raw_builder = self.select_and_build(
            &unspent_transactions,
            outputs,
            return_address,
            attributes.clone(),
        )?;

        let signer = self.signer_manager.create_signer(name, passphrase);

        raw_builder.sign_all(signer)?;

        let tx_aux = raw_builder.to_tx_aux(self.transaction_obfuscation.clone())?;

        Ok(tx_aux)
    }

    #[inline]
    fn obfuscate(&self, signed_transaction: SignedTransaction) -> Result<TxAux> {
        self.transaction_obfuscation.encrypt(signed_transaction)
    }
}

impl<S, F, O> DefaultWalletTransactionBuilder<S, F, O>
where
    S: Storage,
    F: FeeAlgorithm + Clone,
    O: TransactionObfuscation,
{
    /// Creates a new instance of transaction builder
    #[inline]
    pub fn new(
        signer_manager: WalletSignerManager<S>,
        fee_algorithm: F,
        transaction_obfuscation: O,
    ) -> Self {
        Self {
            signer_manager,
            fee_algorithm,
            transaction_obfuscation,
        }
    }

    /// Create a `DummySigner` which signs a transaction with dummy values for fees calculation.
    /// Returns a result of unsigned raw transfer transaction builder
    pub fn select_and_build<'a>(
        &self,
        unspent_transactions: &'a UnspentTransactions,
        outputs: Vec<TxOut>,
        return_address: ExtendedAddr,
        attributes: TxAttributes,
    ) -> Result<RawTransferTransactionBuilder<F>> {
        let output_value = sum_coins(outputs.iter().map(|output| output.value)).chain(|| {
            (
                ErrorKind::IllegalInput,
                "Sum of output values exceeds maximum allowed amount",
            )
        })?;
        let mut fees = Coin::zero();
        let raw_tx_builder = loop {
            let (selected_unspent_txs, change_amount) =
                unspent_transactions.select((output_value + fees).chain(|| {
                    (
                        ErrorKind::IllegalInput,
                        "Sum of output values and fee exceeds maximum allowed amount",
                    )
                })?)?;

            let raw_tx_builder = self.build_raw_transaction(
                &selected_unspent_txs,
                &outputs,
                return_address.clone(),
                change_amount,
                attributes.clone(),
            );

            let new_fees = raw_tx_builder.estimate_fee()?;
            if new_fees > fees {
                fees = new_fees;
            } else {
                break raw_tx_builder;
            }
        };

        Ok(raw_tx_builder)
    }

    fn build_raw_transaction(
        &self,
        selected_unspent_transactions: &SelectedUnspentTransactions<'_>,
        outputs: &[TxOut],
        return_address: ExtendedAddr,
        change_amount: Coin,
        attributes: TxAttributes,
    ) -> RawTransferTransactionBuilder<F> {
        let mut raw_tx_builder =
            RawTransferTransactionBuilder::new(attributes, self.fee_algorithm.clone());
        for input in selected_unspent_transactions.iter() {
            raw_tx_builder.add_input(input.clone());
        }
        for output in outputs.iter() {
            raw_tx_builder.add_output(output.clone());
        }
        if change_amount != Coin::zero() {
            raw_tx_builder.add_output(TxOut::new(return_address, change_amount));
        }

        raw_tx_builder
    }
}

#[cfg(test)]
mod default_wallet_transaction_builder_tests {
    use super::*;

    use parity_scale_codec::{Decode, Encode};

    use chain_core::tx::data::input::{TxoIndex, TxoPointer};
    use chain_core::tx::data::TxId;
    use chain_core::tx::fee::{LinearFee, Milli};
    use chain_core::tx::{PlainTxAux, TransactionId, TxAux, TxEnclaveAux, TxObfuscated};
    use chain_tx_validation::witness::verify_tx_address;
    use client_common::storage::MemoryStorage;
    use client_common::{PrivateKey, Transaction};

    use crate::signer::WalletSignerManager;
    use crate::types::WalletKind;
    use crate::unspent_transactions::{Operation, Sorter};
    use crate::wallet::{DefaultWalletClient, WalletClient};

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
            let txpayload = transaction.encode();

            match transaction {
                SignedTransaction::TransferTransaction(tx, _) => {
                    Ok(TxAux::EnclaveTx(TxEnclaveAux::TransferTx {
                        inputs: tx.inputs.clone(),
                        no_of_outputs: tx.outputs.len() as TxoIndex,
                        payload: TxObfuscated {
                            txid: [0; 32],
                            key_from: 0,
                            init_vector: [0u8; 12],
                            txpayload,
                        },
                    }))
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn check_transaction_building_flow() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        wallet_client
            .new_wallet(name, passphrase, WalletKind::Basic)
            .unwrap();

        let public_keys = vec![
            wallet_client
                .new_public_key(name, passphrase, None)
                .unwrap(),
            wallet_client
                .new_public_key(name, passphrase, None)
                .unwrap(),
            wallet_client
                .new_public_key(name, passphrase, None)
                .unwrap(),
        ];

        let addresses = vec![
            wallet_client
                .new_transfer_address(name, passphrase)
                .unwrap(),
            wallet_client
                .new_transfer_address(name, passphrase)
                .unwrap(),
            wallet_client
                .new_transfer_address(name, passphrase)
                .unwrap(),
            wallet_client
                .new_multisig_transfer_address(
                    name,
                    passphrase,
                    public_keys.clone(),
                    public_keys[0].clone(),
                    1,
                )
                .unwrap(),
        ];

        let mut unspent_transactions = UnspentTransactions::new(vec![
            (
                TxoPointer::new([0; 32], 0),
                TxOut::new(addresses[0].clone(), Coin::new(500).unwrap()),
            ),
            (
                TxoPointer::new([1; 32], 0),
                TxOut::new(addresses[1].clone(), Coin::new(1000).unwrap()),
            ),
            (
                TxoPointer::new([2; 32], 0),
                TxOut::new(addresses[2].clone(), Coin::new(750).unwrap()),
            ),
            (
                TxoPointer::new([3; 32], 0),
                TxOut::new(addresses[3].clone(), Coin::new(1250).unwrap()),
            ),
        ]);
        unspent_transactions.apply_all(&[Operation::Sort(Sorter::HighestValueFirst)]);

        let return_address = wallet_client
            .new_transfer_address(name, passphrase)
            .unwrap();

        let signer_manager = WalletSignerManager::new(storage.clone());
        let fee_algorithm = LinearFee::new(Milli::new(1, 1), Milli::new(1, 1));

        let transaction_builder = DefaultWalletTransactionBuilder::new(
            signer_manager,
            fee_algorithm,
            MockTransactionCipher,
        );

        let outputs = vec![TxOut::new(
            wallet_client
                .new_transfer_address(name, passphrase)
                .unwrap(),
            Coin::new(1000).unwrap(),
        )];
        let attributes = TxAttributes::new(171);

        let tx_aux = transaction_builder
            .build_transfer_tx(
                name,
                passphrase,
                unspent_transactions.clone(),
                outputs,
                return_address,
                attributes,
            )
            .unwrap();

        let fee = fee_algorithm
            .calculate_for_txaux(&tx_aux)
            .unwrap()
            .to_coin();

        match tx_aux {
            TxAux::EnclaveTx(TxEnclaveAux::TransferTx {
                payload: TxObfuscated { txpayload, .. },
                ..
            }) => {
                if let Ok(PlainTxAux::TransferTx(transaction, witness)) =
                    PlainTxAux::decode(&mut txpayload.as_slice())
                {
                    let output_value =
                        sum_coins(transaction.outputs.iter().map(|output| output.value)).unwrap();

                    let input_value = sum_coins(transaction.inputs.iter().map(|input| {
                        if input.id == [3; 32] {
                            unspent_transactions[0].1.value
                        } else if input.id == [1; 32] {
                            unspent_transactions[1].1.value
                        } else if input.id == [2; 32] {
                            unspent_transactions[2].1.value
                        } else {
                            unspent_transactions[0].1.value
                        }
                    }))
                    .unwrap();
                    assert!((output_value + fee).unwrap() <= input_value);

                    for (i, input) in transaction.inputs.iter().enumerate() {
                        let address = if input.id == [3; 32] {
                            unspent_transactions[0].1.address.clone()
                        } else if input.id == [1; 32] {
                            unspent_transactions[1].1.address.clone()
                        } else if input.id == [2; 32] {
                            unspent_transactions[2].1.address.clone()
                        } else {
                            unspent_transactions[0].1.address.clone()
                        };

                        assert!(verify_tx_address(&witness[i], &transaction.id(), &address).is_ok(),)
                    }
                }
            }
            _ => {
                // NOTE: Transaction builder doesn't do account/staking related transactions
                unreachable!()
            }
        }
    }

    #[test]
    fn check_insufficient_balance_flow() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        wallet_client
            .new_wallet(name, passphrase, WalletKind::Basic)
            .unwrap();

        let public_keys = vec![
            wallet_client
                .new_public_key(name, passphrase, None)
                .unwrap(),
            wallet_client
                .new_public_key(name, passphrase, None)
                .unwrap(),
            wallet_client
                .new_public_key(name, passphrase, None)
                .unwrap(),
        ];

        let addresses = vec![
            wallet_client
                .new_transfer_address(name, passphrase)
                .unwrap(),
            wallet_client
                .new_multisig_transfer_address(
                    name,
                    passphrase,
                    public_keys.clone(),
                    public_keys[0].clone(),
                    1,
                )
                .unwrap(),
        ];

        let mut unspent_transactions = UnspentTransactions::new(vec![
            (
                TxoPointer::new([0; 32], 0),
                TxOut::new(addresses[0].clone(), Coin::new(500).unwrap()),
            ),
            (
                TxoPointer::new([1; 32], 0),
                TxOut::new(addresses[1].clone(), Coin::new(1250).unwrap()),
            ),
        ]);
        unspent_transactions.apply_all(&[Operation::Sort(Sorter::HighestValueFirst)]);

        let return_address = wallet_client
            .new_transfer_address(name, passphrase)
            .unwrap();

        let signer_manager = WalletSignerManager::new(storage.clone());
        let fee_algorithm = LinearFee::new(Milli::new(1, 1), Milli::new(1, 1));

        let transaction_builder = DefaultWalletTransactionBuilder::new(
            signer_manager,
            fee_algorithm,
            MockTransactionCipher,
        );

        let outputs = vec![TxOut::new(
            wallet_client
                .new_transfer_address(name, passphrase)
                .unwrap(),
            Coin::new(1700).unwrap(),
        )];
        let attributes = TxAttributes::new(171);

        assert_eq!(
            ErrorKind::InvalidInput,
            transaction_builder
                .build_transfer_tx(
                    name,
                    passphrase,
                    unspent_transactions.clone(),
                    outputs,
                    return_address,
                    attributes,
                )
                .unwrap_err()
                .kind()
        );
    }
}
