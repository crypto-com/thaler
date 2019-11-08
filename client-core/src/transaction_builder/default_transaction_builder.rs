use secstr::SecUtf8;

use crate::signer::DummySigner;
use chain_core::init::coin::{sum_coins, Coin};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::Tx;
use chain_core::tx::fee::FeeAlgorithm;
use chain_core::tx::{TransactionId, TxAux};
use client_common::{Error, ErrorKind, Result, ResultExt, SignedTransaction};

use crate::{
    SelectedUnspentTransactions, Signer, TransactionBuilder, TransactionObfuscation,
    UnspentTransactions,
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
/// 6. Encrypt/obfuscate transaction.
/// 7. Calculate `new_fees`.
/// 8. If `new_fees > fees`, then change `fees = new_fees` and goto step 3, otherwise return signed transaction.
///
#[derive(Debug)]
pub struct DefaultTransactionBuilder<S, F, O>
where
    S: Signer,
    F: FeeAlgorithm,
    O: TransactionObfuscation,
{
    signer: S,
    fee_algorithm: F,
    transaction_obfuscation: O,
}

impl<S, F, O> DefaultTransactionBuilder<S, F, O>
where
    S: Signer,
    F: FeeAlgorithm,
    O: TransactionObfuscation,
{
    ///  Create a `DummySigner` which signs a transaction with dummy values for fees calculation.
    /// Returns a result of fees , `Tx` and selected unspent transactions
    pub fn get_fees<'a>(
        &self,
        total_pubkeys_len: usize,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        return_address: ExtendedAddr,
        unspent_transactions: &'a UnspentTransactions,
    ) -> Result<(Coin, Tx, SelectedUnspentTransactions<'a>)> {
        let output_value = sum_coins(outputs.iter().map(|output| output.value)).chain(|| {
            (
                ErrorKind::IllegalInput,
                "Sum of output values exceeds maximum allowed amount",
            )
        })?;
        let mut fees = Coin::zero();
        let dummy_signer = DummySigner();
        let (tx, selected_unspent_txs) = loop {
            let (selected_unspent_txs, difference_amount) =
                unspent_transactions.select((output_value + fees).chain(|| {
                    (
                        ErrorKind::IllegalInput,
                        "Sum of output values and fee exceeds maximum allowed amount",
                    )
                })?)?;

            let tx = build_transaction(
                &selected_unspent_txs,
                outputs.clone(),
                attributes.clone(),
                difference_amount,
                return_address.clone(),
            );

            // use the dummy signer to sign the selected unspent transactions
            let witness = dummy_signer.sign_txs(total_pubkeys_len, &selected_unspent_txs)?;
            let tx_aux = dummy_signer.mock_txaux_for_tx(tx.clone(), witness);
            let new_fees = self
                .fee_algorithm
                .calculate_for_txaux(&tx_aux)
                .chain(|| {
                    (
                        ErrorKind::IllegalInput,
                        "Fee exceeds maximum allowed amount",
                    )
                })?
                .to_coin();

            if new_fees > fees {
                fees = new_fees;
            } else {
                break (tx, selected_unspent_txs);
            }
        };
        Ok((fees, tx, selected_unspent_txs))
    }
}

impl<S, F, O> DefaultTransactionBuilder<S, F, O>
where
    S: Signer,
    F: FeeAlgorithm,
    O: TransactionObfuscation,
{
    /// Creates a new instance of transaction builder
    #[inline]
    pub fn new(signer: S, fee_algorithm: F, transaction_obfuscation: O) -> Self {
        Self {
            signer,
            fee_algorithm,
            transaction_obfuscation,
        }
    }
}

impl<S, F, O> TransactionBuilder for DefaultTransactionBuilder<S, F, O>
where
    S: Signer,
    F: FeeAlgorithm,
    O: TransactionObfuscation,
{
    fn build(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        unspent_transactions: UnspentTransactions,
        return_address: ExtendedAddr,
    ) -> Result<TxAux> {
        let total_pubkeys_len = 2;
        let (calculated_fees, tx, selected_unspent_txs) = self.get_fees(
            total_pubkeys_len,
            outputs,
            attributes.clone(),
            return_address,
            &unspent_transactions,
        )?;
        let witness = self
            .signer
            .sign(name, passphrase, tx.id(), &selected_unspent_txs)?;

        let signed_transaction = SignedTransaction::TransferTransaction(tx, witness);
        let tx_aux = self.transaction_obfuscation.encrypt(signed_transaction)?;
        let fees = self
            .fee_algorithm
            .calculate_for_txaux(&tx_aux)
            .chain(|| {
                (
                    ErrorKind::IllegalInput,
                    "Fee exceeds maximum allowed amount",
                )
            })?
            .to_coin();
        if calculated_fees >= fees {
            Ok(tx_aux)
        } else {
            Err(Error::new(ErrorKind::MultiSigError, "calculate fee error"))
        }
    }

    #[inline]
    fn obfuscate(&self, signed_transaction: SignedTransaction) -> Result<TxAux> {
        self.transaction_obfuscation.encrypt(signed_transaction)
    }
}

fn build_transaction(
    selected_unspent_transactions: &SelectedUnspentTransactions<'_>,
    mut outputs: Vec<TxOut>,
    attributes: TxAttributes,
    difference_amount: Coin,
    return_address: ExtendedAddr,
) -> Tx {
    if difference_amount != Coin::zero() {
        outputs.push(TxOut::new(return_address.clone(), difference_amount));
    }

    Tx {
        inputs: selected_unspent_transactions
            .iter()
            .map(|(input, _)| input.clone())
            .collect(),
        outputs,
        attributes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use parity_scale_codec::{Decode, Encode};

    use chain_core::tx::data::input::{TxoIndex, TxoPointer};
    use chain_core::tx::data::TxId;
    use chain_core::tx::fee::{LinearFee, Milli};
    use chain_core::tx::{PlainTxAux, TxAux, TxEnclaveAux, TxObfuscated};
    use chain_tx_validation::witness::verify_tx_address;
    use client_common::storage::MemoryStorage;
    use client_common::{PrivateKey, Transaction};

    use crate::signer::DefaultSigner;
    use crate::types::WalletKind;
    use crate::unspent_transactions::{Operation, Sorter};
    use crate::wallet::{DefaultWalletClient, WalletClient};

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
                    3,
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

        let signer = DefaultSigner::new(storage.clone());
        let fee_algorithm = LinearFee::new(Milli::new(1, 1), Milli::new(1, 1));

        let transaction_builder =
            DefaultTransactionBuilder::new(signer, fee_algorithm, MockTransactionCipher);

        let outputs = vec![TxOut::new(
            wallet_client
                .new_transfer_address(name, passphrase)
                .unwrap(),
            Coin::new(1000).unwrap(),
        )];
        let attributes = TxAttributes::new(171);

        let tx_aux = transaction_builder
            .build(
                name,
                passphrase,
                outputs,
                attributes,
                unspent_transactions.clone(),
                return_address,
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
                    3,
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

        let signer = DefaultSigner::new(storage.clone());
        let fee_algorithm = LinearFee::new(Milli::new(1, 1), Milli::new(1, 1));

        let transaction_builder =
            DefaultTransactionBuilder::new(signer, fee_algorithm, MockTransactionCipher);

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
                .build(
                    name,
                    passphrase,
                    outputs,
                    attributes,
                    unspent_transactions.clone(),
                    return_address,
                )
                .unwrap_err()
                .kind()
        );
    }
}
