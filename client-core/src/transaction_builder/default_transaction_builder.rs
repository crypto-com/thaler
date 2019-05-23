use failure::ResultExt;
use secp256k1::RecoveryId;
use secstr::SecUtf8;

use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::Tx;
use chain_core::tx::fee::{Fee, FeeAlgorithm};
use chain_core::tx::witness::{EcdsaSignature, TxInWitness, TxWitness};
use chain_core::tx::TxAux;
use client_common::{ErrorKind, Result};

use crate::{TransactionBuilder, WalletClient};

/// Default implementation of `TransactionBuilder`
///
/// # Algorithm
///
/// 1. Retrieve a list of unspent transactions and sort it in descending order of amounts.
/// 2. Calculate the number of unspent transactions to select from beginning and the amount to be returned back from
///    transaction estimation algorithm.
/// 3. Build a transaction from above data.
///
/// # Transaction Estimation Algorithm
///
/// 1. Initialize `fee = 0`.
/// 2. Build a transaction with zero fee.
/// 3. Calculate `new_fee`.
/// 4. Do steps 5 - 8 until `fee < new_fee`.
/// 5. Calculate amount to transfer (fee + sum of amounts of outputs).
/// 6. Select unspent transactions from beginning such that amount of unspent transactions is greater than amount to
///    transfer.
/// 7. Add dummy values for output and witnesses and calculate `revised_fee`.
/// 8. `fee = new_fee` and `new_fee = revised_fee`.
/// 9. When the above loop is done, return number of selected unspent transactions and difference amount.
#[derive(Debug)]
pub struct DefaultTransactionBuilder<F>
where
    F: FeeAlgorithm,
{
    fee_algorithm: F,
}

impl<F> DefaultTransactionBuilder<F>
where
    F: FeeAlgorithm,
{
    /// Creates a new instance of `DefaultTransactionBuilder`
    pub fn new(fee_algorithm: F) -> Self {
        Self { fee_algorithm }
    }

    /// Adds amounts in all outputs and fee
    fn amount_to_transfer(&self, outputs: &[TxOut], fee: Fee) -> Result<Coin> {
        let mut amount_to_transfer = fee.to_coin();
        for output in outputs.iter() {
            amount_to_transfer =
                (amount_to_transfer + output.value).context(ErrorKind::BalanceAdditionError)?;
        }

        Ok(amount_to_transfer)
    }

    /// Returns the index until which transactions were selected and difference amount between selected transactions
    /// and amount to transfer (`transferred_amount - amount_to_transfer`)
    fn select_transactions(
        &self,
        unspent_transactions: &[(TxoPointer, Coin)],
        amount_to_transfer: Coin,
    ) -> Result<(usize, Coin)> {
        let mut transferred_amount = Coin::zero();

        for (i, (_, value)) in unspent_transactions.iter().enumerate() {
            transferred_amount =
                (transferred_amount + value).context(ErrorKind::BalanceAdditionError)?;

            if transferred_amount >= amount_to_transfer {
                return Ok((
                    i + 1,
                    (transferred_amount - amount_to_transfer)
                        .context(ErrorKind::BalanceAdditionError)?,
                ));
            }
        }

        Err(ErrorKind::InsufficientBalance.into())
    }

    /// Signs the transaction and returns witnesses
    fn witnesses<W: WalletClient>(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        wallet_client: &W,
        transaction: &Tx,
    ) -> Result<TxWitness> {
        let mut witnesses = Vec::with_capacity(transaction.inputs.len());

        for input in &transaction.inputs {
            let input = wallet_client.output(&input.id, input.index)?;

            match wallet_client.private_key(name, passphrase, &input.address)? {
                None => return Err(ErrorKind::PrivateKeyNotFound.into()),
                Some(private_key) => witnesses.push(private_key.sign(&transaction.id())?),
            }
        }

        Ok(witnesses.into())
    }

    /// Returns `(select_until, difference_amount)`
    /// - `select_until`: It is the number of the unspent transactions to take from beginning of given unspent
    ///   transactions to build valid transaction
    /// - `difference_amount`: Amount to return back to sender's wallet
    fn transaction_estimate(
        &self,
        outputs: &[TxOut],
        attributes: &TxAttributes,
        unspent_transactions: &[(TxoPointer, Coin)],
    ) -> Result<(usize, Coin)> {
        let mut fee = Fee::new(Coin::zero());
        let (mut tx_aux, mut selected_until, mut difference_amount) =
            self.transaction_estimate_with_fee(outputs, attributes, unspent_transactions, fee)?;
        let mut new_fee = self
            .fee_algorithm
            .calculate_for_txaux(&tx_aux)
            .context(ErrorKind::BalanceAdditionError)?;

        while fee < new_fee {
            fee = new_fee;
            let (new_tx_aux, new_selected_until, new_difference_amount) =
                self.transaction_estimate_with_fee(outputs, attributes, unspent_transactions, fee)?;

            tx_aux = new_tx_aux;
            selected_until = new_selected_until;
            difference_amount = new_difference_amount;

            new_fee = self
                .fee_algorithm
                .calculate_for_txaux(&tx_aux)
                .context(ErrorKind::BalanceAdditionError)?;
        }

        Ok((selected_until, difference_amount))
    }

    /// Returns `(dummy_transaction, select_until, difference_amount)`
    /// - `dummy_transaction`: Transaction with dummy values used for fee calculation
    /// - `select_until`: It is the number of the unspent transactions to take from beginning of given unspent
    ///   transactions to build valid transaction
    /// - `difference_amount`: Amount to return back to sender's wallet
    fn transaction_estimate_with_fee(
        &self,
        outputs: &[TxOut],
        attributes: &TxAttributes,
        unspent_transactions: &[(TxoPointer, Coin)],
        fee: Fee,
    ) -> Result<(TxAux, usize, Coin)> {
        let amount_to_transfer = self.amount_to_transfer(&outputs, fee)?;

        let (selected_until, difference_amount) =
            self.select_transactions(unspent_transactions, amount_to_transfer)?;

        let inputs = unspent_transactions[..selected_until]
            .iter()
            .map(|(input, _)| input.clone())
            .collect::<Vec<TxoPointer>>();

        let transaction_estimate = if Coin::zero() == difference_amount {
            Tx {
                inputs,
                outputs: outputs.to_vec(),
                attributes: attributes.clone(),
            }
        } else {
            let mut outputs = outputs.to_vec();
            outputs.push(TxOut {
                address: ExtendedAddr::BasicRedeem(RedeemAddress([
                    0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65, 0x04, 0x73, 0x80,
                    0x89, 0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4,
                ])),
                value: Coin::zero(),
                valid_from: None,
            });

            Tx {
                inputs,
                outputs,
                attributes: attributes.clone(),
            }
        };

        let witness_estimate = self.witness_estimate(selected_until);

        let tx_aux = TxAux::TransferTx(transaction_estimate, witness_estimate);

        Ok((tx_aux, selected_until, difference_amount))
    }

    /// Returns dummy witnesses
    fn witness_estimate(&self, num_inputs: usize) -> TxWitness {
        vec![
            TxInWitness::BasicRedeem(
                EcdsaSignature::from_compact(&[0; 64], RecoveryId::from_i32(0).unwrap()).unwrap(),
            );
            num_inputs
        ]
        .into()
    }

    /// Builds final transaction
    fn build_from_estimate<W: WalletClient>(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        mut transaction: Tx,
        difference_amount: Coin,
        wallet_client: &W,
    ) -> Result<TxAux> {
        if Coin::zero() != difference_amount {
            let new_address = wallet_client.new_address(name, passphrase)?;
            transaction
                .outputs
                .push(TxOut::new(new_address, difference_amount));
        }

        let witnesses = self.witnesses(name, passphrase, wallet_client, &transaction)?;

        Ok(TxAux::TransferTx(transaction, witnesses))
    }
}

impl<F> TransactionBuilder for DefaultTransactionBuilder<F>
where
    F: FeeAlgorithm,
{
    fn build<W: WalletClient>(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        wallet_client: &W,
    ) -> Result<TxAux> {
        let mut unspent_transactions = wallet_client.unspent_transactions(name, passphrase)?;
        unspent_transactions.sort_by(|a, b| a.1.cmp(&b.1).reverse());

        let (select_until, difference_amount) =
            self.transaction_estimate(&outputs, &attributes, &unspent_transactions)?;

        unspent_transactions.truncate(select_until);

        let transaction = Tx {
            inputs: unspent_transactions
                .into_iter()
                .map(|(input, _)| input)
                .collect(),
            outputs,
            attributes,
        };

        self.build_from_estimate(
            name,
            passphrase,
            transaction,
            difference_amount,
            wallet_client,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::sum_coins;
    use chain_core::tx::data::address::ExtendedAddr;
    use chain_core::tx::data::TxId;
    use chain_core::tx::fee::{LinearFee, Milli};
    use client_common::balance::TransactionChange;

    use crate::{PrivateKey, PublicKey};

    struct MockWalletClient {
        txid_0: TxId,
        txid_1: TxId,
        txid_2: TxId,
        addr_0: ExtendedAddr,
        addr_1: ExtendedAddr,
        addr_2: ExtendedAddr,
    }

    impl MockWalletClient {
        fn assert_fee(&self, fee: Fee, transaction: Tx) {
            let input_amounts = transaction
                .inputs
                .iter()
                .map(|input| self.output(&input.id, input.index))
                .collect::<Result<Vec<TxOut>>>()
                .unwrap()
                .into_iter()
                .map(|input| input.value)
                .collect::<Vec<Coin>>();

            let input_amount = sum_coins(input_amounts.into_iter()).unwrap();

            let output_amounts = transaction
                .outputs
                .into_iter()
                .map(|output| output.value)
                .collect::<Vec<Coin>>();

            let output_amount = sum_coins(output_amounts.into_iter()).unwrap();

            assert!(fee.to_coin() <= (input_amount - output_amount).unwrap());
        }
    }

    impl Default for MockWalletClient {
        fn default() -> Self {
            Self {
                txid_0: [0u8; 32],
                txid_1: [1u8; 32],
                txid_2: [2u8; 32],
                addr_0: ExtendedAddr::BasicRedeem(
                    RedeemAddress::from_str("1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
                ),
                addr_1: ExtendedAddr::BasicRedeem(
                    RedeemAddress::from_str("790661a2fd9da3fee53caab80859ecae125a20a5").unwrap(),
                ),
                addr_2: ExtendedAddr::BasicRedeem(
                    RedeemAddress::from_str("780661a2fd9da3fee53caab80859ecae105a20b6").unwrap(),
                ),
            }
        }
    }

    impl WalletClient for MockWalletClient {
        fn wallets(&self) -> Result<Vec<String>> {
            unreachable!()
        }

        fn new_wallet(&self, _: &str, _: &SecUtf8) -> Result<String> {
            unreachable!()
        }

        fn private_keys(&self, _: &str, _: &SecUtf8) -> Result<Vec<PrivateKey>> {
            unreachable!()
        }

        fn public_keys(&self, _: &str, _: &SecUtf8) -> Result<Vec<PublicKey>> {
            unreachable!()
        }

        fn addresses(&self, _: &str, _: &SecUtf8) -> Result<Vec<ExtendedAddr>> {
            unreachable!()
        }

        fn private_key(
            &self,
            _: &str,
            _: &SecUtf8,
            address: &ExtendedAddr,
        ) -> Result<Option<PrivateKey>> {
            if address == &self.addr_0 {
                Ok(Some(
                    PrivateKey::deserialize_from(&[
                        197, 83, 160, 54, 4, 35, 93, 248, 252, 209, 79, 198, 209, 229, 177, 138,
                        33, 159, 188, 198, 233, 62, 255, 207, 207, 118, 142, 41, 119, 167, 78, 194,
                    ])
                    .unwrap(),
                ))
            } else if address == &self.addr_1 {
                Ok(Some(
                    PrivateKey::deserialize_from(&[
                        197, 83, 160, 54, 4, 35, 93, 248, 252, 209, 79, 198, 209, 229, 177, 138,
                        33, 159, 188, 198, 233, 62, 255, 207, 207, 118, 142, 41, 119, 167, 78, 195,
                    ])
                    .unwrap(),
                ))
            } else {
                Ok(Some(
                    PrivateKey::deserialize_from(&[
                        197, 83, 160, 54, 4, 35, 93, 248, 252, 209, 79, 198, 209, 229, 177, 138,
                        33, 159, 188, 198, 233, 62, 255, 207, 207, 118, 142, 41, 119, 167, 78, 196,
                    ])
                    .unwrap(),
                ))
            }
        }

        fn new_public_key(&self, _: &str, _: &SecUtf8) -> Result<PublicKey> {
            unreachable!()
        }

        fn new_address(&self, _: &str, _: &SecUtf8) -> Result<ExtendedAddr> {
            Ok(ExtendedAddr::BasicRedeem(
                RedeemAddress::from_str("1fdf22497167a793ca794963ad6c95e6ffa0baba").unwrap(),
            ))
        }

        fn balance(&self, _: &str, _: &SecUtf8) -> Result<Coin> {
            unreachable!()
        }

        fn history(&self, _: &str, _: &SecUtf8) -> Result<Vec<TransactionChange>> {
            unreachable!()
        }

        fn unspent_transactions(&self, _: &str, _: &SecUtf8) -> Result<Vec<(TxoPointer, Coin)>> {
            Ok(vec![
                (
                    TxoPointer {
                        id: self.txid_0,
                        index: 0,
                    },
                    Coin::new(200).unwrap(),
                ),
                (
                    TxoPointer {
                        id: self.txid_1,
                        index: 0,
                    },
                    Coin::new(217).unwrap(),
                ),
                (
                    TxoPointer {
                        id: self.txid_2,
                        index: 0,
                    },
                    Coin::new(100).unwrap(),
                ),
            ])
        }

        fn output(&self, id: &TxId, _: usize) -> Result<TxOut> {
            if &self.txid_0 == id {
                Ok(TxOut {
                    address: self.addr_0.clone(),
                    value: Coin::new(200).unwrap(),
                    valid_from: None,
                })
            } else if &self.txid_1 == id {
                Ok(TxOut {
                    address: self.addr_1.clone(),
                    value: Coin::new(217).unwrap(),
                    valid_from: None,
                })
            } else {
                Ok(TxOut {
                    address: self.addr_2.clone(),
                    value: Coin::new(100).unwrap(),
                    valid_from: None,
                })
            }
        }

        fn create_and_broadcast_transaction(
            &self,
            _: &str,
            _: &SecUtf8,
            _: Vec<TxOut>,
            _: TxAttributes,
        ) -> Result<()> {
            unreachable!()
        }

        fn sync(&self) -> Result<()> {
            unreachable!()
        }

        fn sync_all(&self) -> Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn check_with_exact_fee_match() {
        let fee_algorithm = LinearFee::new(Milli::new(1, 1), Milli::new(1, 1));
        let transaction_builder = DefaultTransactionBuilder::new(fee_algorithm);

        let wallet_client = MockWalletClient::default();

        let tx_aux = transaction_builder
            .build(
                "name",
                &SecUtf8::from("passphrase"),
                vec![TxOut {
                    address: ExtendedAddr::BasicRedeem(
                        RedeemAddress::from_str("790661a2fd9da3fee53caab80859ecae125a20b4")
                            .unwrap(),
                    ),
                    value: Coin::new(40).unwrap(),
                    valid_from: None,
                }],
                TxAttributes::new(171),
                &wallet_client,
            )
            .expect("Unable to build transaction");

        println!("{:?}", tx_aux);

        let fee = fee_algorithm.calculate_for_txaux(&tx_aux).unwrap();

        match tx_aux {
            TxAux::TransferTx(tx, _) => {
                assert_eq!(1, tx.outputs.len());
                wallet_client.assert_fee(fee, tx);
            }
        }
    }

    #[test]
    fn check_with_fee() {
        let fee_algorithm = LinearFee::new(Milli::new(1, 1), Milli::new(1, 1));
        let transaction_builder = DefaultTransactionBuilder::new(fee_algorithm);

        let wallet_client = MockWalletClient::default();

        let tx_aux = transaction_builder
            .build(
                "name",
                &SecUtf8::from("passphrase"),
                vec![TxOut {
                    address: ExtendedAddr::BasicRedeem(
                        RedeemAddress::from_str("790661a2fd9da3fee53caab80859ecae125a20b4")
                            .unwrap(),
                    ),
                    value: Coin::new(30).unwrap(),
                    valid_from: None,
                }],
                TxAttributes::new(171),
                &wallet_client,
            )
            .expect("Unable to build transaction");

        let fee = fee_algorithm.calculate_for_txaux(&tx_aux).unwrap();

        match tx_aux {
            TxAux::TransferTx(tx, _) => {
                assert_eq!(2, tx.outputs.len());
                wallet_client.assert_fee(fee, tx);
            }
        }
    }

    #[test]
    fn check_insufficient_balance_with_fee() {
        let fee_algorithm = LinearFee::new(Milli::new(1, 1), Milli::new(1, 1));
        let transaction_builder = DefaultTransactionBuilder::new(fee_algorithm);

        let wallet_client = MockWalletClient::default();

        let tx_aux = transaction_builder.build(
            "name",
            &SecUtf8::from("passphrase"),
            vec![TxOut {
                address: ExtendedAddr::BasicRedeem(
                    RedeemAddress::from_str("790661a2fd9da3fee53caab80859ecae125a20b4").unwrap(),
                ),
                value: Coin::new(400).unwrap(),
                valid_from: None,
            }],
            TxAttributes::new(171),
            &wallet_client,
        );

        assert!(tx_aux.is_err());
        assert_eq!(ErrorKind::InsufficientBalance, tx_aux.unwrap_err().kind());
    }
}
