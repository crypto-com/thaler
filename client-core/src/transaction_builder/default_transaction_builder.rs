use failure::ResultExt;
use secstr::SecStr;

use chain_core::init::coin::Coin;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::Tx;
use chain_core::tx::fee::{Fee, FeeAlgorithm};
use chain_core::tx::witness::TxWitness;
use chain_core::tx::TxAux;
use client_common::{ErrorKind, Result};

use crate::{TransactionBuilder, WalletClient};

/// Default implementation of `TransactionBuilder`
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

    fn amount_to_transfer(&self, outputs: &[TxOut], fee: Fee) -> Result<Coin> {
        let mut amount_to_transfer = fee.to_coin();
        for output in outputs.iter() {
            amount_to_transfer =
                (amount_to_transfer + output.value).context(ErrorKind::BalanceAdditionError)?;
        }

        Ok(amount_to_transfer)
    }

    fn select_transactions(
        &self,
        mut unspent_transactions: Vec<(TxoPointer, Coin)>,
        amount_to_transfer: Coin,
    ) -> Result<(Vec<TxoPointer>, Coin)> {
        unspent_transactions.sort_by(|a, b| a.1.cmp(&b.1).reverse());

        let mut selected_unspent_transactions = Vec::new();
        let mut transferred_amount = Coin::zero();
        for (unspent_transaction, value) in unspent_transactions {
            selected_unspent_transactions.push(unspent_transaction);
            transferred_amount =
                (transferred_amount + value).context(ErrorKind::BalanceAdditionError)?;

            if transferred_amount >= amount_to_transfer {
                break;
            }
        }

        if transferred_amount < amount_to_transfer {
            Err(ErrorKind::InsufficientBalance.into())
        } else {
            Ok((
                selected_unspent_transactions,
                (transferred_amount - amount_to_transfer)
                    .context(ErrorKind::BalanceAdditionError)?,
            ))
        }
    }

    fn witnesses<W: WalletClient>(
        &self,
        name: &str,
        passphrase: &SecStr,
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

    fn build_with_fee<W: WalletClient>(
        &self,
        name: &str,
        passphrase: &SecStr,
        mut outputs: Vec<TxOut>,
        attributes: TxAttributes,
        wallet_client: &W,
        fee: Fee,
    ) -> Result<TxAux> {
        let unspent_transactions = wallet_client.unspent_transactions(name, passphrase)?;

        let amount_to_transfer = self.amount_to_transfer(&outputs, fee)?;
        let (selected_unspent_transactions, difference_amount) =
            self.select_transactions(unspent_transactions, amount_to_transfer)?;

        let transaction = if Coin::zero() == difference_amount {
            Tx {
                inputs: selected_unspent_transactions,
                outputs,
                attributes,
            }
        } else {
            let new_address = wallet_client.new_address(name, passphrase)?;
            outputs.push(TxOut::new(new_address, difference_amount));

            Tx {
                inputs: selected_unspent_transactions,
                outputs,
                attributes,
            }
        };

        let witnesses = self.witnesses(name, passphrase, wallet_client, &transaction)?;

        Ok(TxAux::new(transaction, witnesses))
    }
}

impl<F> TransactionBuilder for DefaultTransactionBuilder<F>
where
    F: FeeAlgorithm,
{
    fn build<W: WalletClient>(
        &self,
        name: &str,
        passphrase: &SecStr,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        wallet_client: &W,
    ) -> Result<TxAux> {
        let mut fee = Fee::new(Coin::zero());
        let mut tx_aux = self.build_with_fee(
            name,
            passphrase,
            outputs.clone(),
            attributes.clone(),
            wallet_client,
            fee,
        )?;
        let mut new_fee = self
            .fee_algorithm
            .calculate_for_txaux(&tx_aux)
            .context(ErrorKind::BalanceAdditionError)?;

        while fee < new_fee {
            fee = new_fee;
            tx_aux = self.build_with_fee(
                name,
                passphrase,
                outputs.clone(),
                attributes.clone(),
                wallet_client,
                fee,
            )?;
            new_fee = self
                .fee_algorithm
                .calculate_for_txaux(&tx_aux)
                .context(ErrorKind::BalanceAdditionError)?;
        }

        Ok(tx_aux)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use chain_core::init::address::RedeemAddress;
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

    impl Default for MockWalletClient {
        fn default() -> Self {
            Self {
                txid_0: TxId::repeat_byte(0),
                txid_1: TxId::repeat_byte(1),
                txid_2: TxId::repeat_byte(2),
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

        fn new_wallet(&self, _: &str, _: &SecStr) -> Result<String> {
            unreachable!()
        }

        fn private_keys(&self, _: &str, _: &SecStr) -> Result<Vec<PrivateKey>> {
            unreachable!()
        }

        fn public_keys(&self, _: &str, _: &SecStr) -> Result<Vec<PublicKey>> {
            unreachable!()
        }

        fn addresses(&self, _: &str, _: &SecStr) -> Result<Vec<ExtendedAddr>> {
            unreachable!()
        }

        fn private_key(
            &self,
            _: &str,
            _: &SecStr,
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

        fn new_public_key(&self, _: &str, _: &SecStr) -> Result<PublicKey> {
            unreachable!()
        }

        fn new_address(&self, _: &str, _: &SecStr) -> Result<ExtendedAddr> {
            Ok(ExtendedAddr::BasicRedeem(
                RedeemAddress::from_str("1fdf22497167a793ca794963ad6c95e6ffa0baba").unwrap(),
            ))
        }

        fn balance(&self, _: &str, _: &SecStr) -> Result<Coin> {
            unreachable!()
        }

        fn history(&self, _: &str, _: &SecStr) -> Result<Vec<TransactionChange>> {
            unreachable!()
        }

        fn unspent_transactions(&self, _: &str, _: &SecStr) -> Result<Vec<(TxoPointer, Coin)>> {
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
            _: &SecStr,
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
                &SecStr::from("passphrase"),
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

        match tx_aux {
            TxAux::TransferTx(tx, _) => assert_eq!(1, tx.outputs.len()),
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
                &SecStr::from("passphrase"),
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

        match tx_aux {
            TxAux::TransferTx(tx, _) => assert_eq!(2, tx.outputs.len()),
        }
    }

    #[test]
    fn check_insufficient_balance_with_fee() {
        let fee_algorithm = LinearFee::new(Milli::new(1, 1), Milli::new(1, 1));
        let transaction_builder = DefaultTransactionBuilder::new(fee_algorithm);

        let wallet_client = MockWalletClient::default();

        let tx_aux = transaction_builder.build(
            "name",
            &SecStr::from("passphrase"),
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
