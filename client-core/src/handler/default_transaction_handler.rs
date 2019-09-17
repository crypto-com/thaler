use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use secstr::SecUtf8;

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::TxId;
use chain_core::tx::TransactionId;
use client_common::{Error, ErrorKind, Result, ResultExt, Storage, Transaction};

use crate::service::{WalletService, WalletStateService};
use crate::types::{BalanceChange, TransactionChange, TransactionInput, TransactionType};
use crate::{TransactionHandler, WalletStateMemento};

/// Default implementation of `TransactionHandler`
#[derive(Clone)]
pub struct DefaultTransactionHandler<S>
where
    S: Storage,
{
    wallet_service: WalletService<S>,
    wallet_state_service: WalletStateService<S>,
}

impl<S> DefaultTransactionHandler<S>
where
    S: Storage + Clone,
{
    /// Creates a new instance of `DefaultTransactionHandler`
    #[inline]
    pub fn new(storage: S) -> Self {
        Self {
            wallet_service: WalletService::new(storage.clone()),
            wallet_state_service: WalletStateService::new(storage),
        }
    }
}

impl<S> TransactionHandler for DefaultTransactionHandler<S>
where
    S: Storage,
{
    fn on_next(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        transaction: Transaction,
        block_height: u64,
        block_time: DateTime<Utc>,
    ) -> Result<()> {
        let transaction_id = transaction.id();
        let inputs = self.decorate_inputs(name, passphrase, transaction.inputs().to_vec())?;
        let outputs = transaction.outputs().to_vec();
        let transaction_type = TransactionType::from(&transaction);
        let balance_change =
            self.calculate_balance_change(name, passphrase, &transaction_id, &inputs, &outputs)?;

        let transaction_change = TransactionChange {
            transaction_id,
            inputs,
            outputs,
            balance_change,
            transaction_type,
            block_height,
            block_time,
        };

        self.on_transaction_change(name, passphrase, transaction_change)
    }
}

impl<S> DefaultTransactionHandler<S>
where
    S: Storage,
{
    fn on_transaction_change(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        transaction_change: TransactionChange,
    ) -> Result<()> {
        let mut memento = WalletStateMemento::default();

        for input in transaction_change.inputs.iter() {
            memento.remove_unspent_transaction(input.pointer.clone());
        }

        let transfer_addresses = self.wallet_service.transfer_addresses(name, passphrase)?;

        for (i, output) in transaction_change.outputs.iter().enumerate() {
            // Only add unspent transaction if output address belongs to current wallet
            if transfer_addresses.contains(&output.address) {
                memento.add_unspent_transaction(
                    TxoPointer::new(transaction_change.transaction_id, i),
                    output.clone(),
                );
            }
        }

        memento.add_transaction_change(transaction_change);

        self.wallet_state_service
            .apply_memento(name, passphrase, &memento)
    }

    fn decorate_inputs(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        raw_inputs: Vec<TxoPointer>,
    ) -> Result<Vec<TransactionInput>> {
        raw_inputs
            .into_iter()
            .map(|raw_input| {
                let output = self
                    .wallet_state_service
                    .get_output(name, passphrase, &raw_input)?;
                Ok(TransactionInput {
                    pointer: raw_input,
                    output,
                })
            })
            .collect()
    }

    fn calculate_balance_change(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        transaction_id: &TxId,
        inputs: &[TransactionInput],
        outputs: &[TxOut],
    ) -> Result<BalanceChange> {
        let transfer_addresses = self.wallet_service.transfer_addresses(name, passphrase)?;

        let total_input_amount = get_total_input_amount(&inputs)?;
        let input_balance_change = get_input_balance_change(&inputs, &transfer_addresses)?;
        let total_output_amount = get_total_output_amount(&outputs)?;
        let output_balance_change = get_output_balance_change(&outputs, &transfer_addresses)?;

        match (total_input_amount, input_balance_change) {
            (Some(total_input_amount), Some(input_balance_change)) => {
                if total_input_amount != input_balance_change {
                    Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "Transaction ({}) contains inputs from multiple wallets: Can't handle such transactions", 
                            hex::encode(&transaction_id)
                        )
                    ))
                } else {
                    let fee = (total_input_amount - total_output_amount).chain(|| {
                        (
                            ErrorKind::IllegalInput,
                            format!(
                                "Output amount is greater than input amount in transaction: {}",
                                hex::encode(&transaction_id)
                            ),
                        )
                    })?;

                    let total_value = (total_input_amount - output_balance_change)
                        .expect("Output balance change is greater than input amount");

                    let value = (total_value - fee).expect("Fee is greater than total value");

                    Ok(BalanceChange::Outgoing { value, fee })
                }
            }
            (_, None) => {
                if Coin::zero() == output_balance_change {
                    Ok(BalanceChange::NoChange)
                } else {
                    Ok(BalanceChange::Incoming {
                        value: output_balance_change,
                    })
                }
            }
            (None, Some(_)) => Err(Error::new(
                ErrorKind::InternalError,
                "There shouldn't be an input balance change if total input amount is none",
            )),
        }
    }
}

fn get_input_balance_change(
    inputs: &[TransactionInput],
    transfer_addresses: &BTreeSet<ExtendedAddr>,
) -> Result<Option<Coin>> {
    if inputs.is_empty() {
        return Ok(None);
    }

    let mut amount = Coin::zero();

    for input in inputs.iter() {
        if let Some(ref output) = input.output {
            if transfer_addresses.contains(&output.address) {
                amount = (amount + output.value).chain(|| {
                    (
                        ErrorKind::IllegalInput,
                        "Input balance change exceeded maximum allowed value",
                    )
                })?;
            }
        }
    }

    if Coin::zero() == amount {
        Ok(None)
    } else {
        Ok(Some(amount))
    }
}

fn get_total_input_amount(inputs: &[TransactionInput]) -> Result<Option<Coin>> {
    if inputs.is_empty() {
        return Ok(None);
    }

    let mut amount = Coin::zero();

    for input in inputs.iter() {
        if let Some(ref output) = input.output {
            amount = (amount + output.value).chain(|| {
                (
                    ErrorKind::IllegalInput,
                    "Total input amount exceeded maximum allowed value",
                )
            })?;
        } else {
            return Ok(None);
        }
    }

    Ok(Some(amount))
}

fn get_output_balance_change(
    outputs: &[TxOut],
    transfer_addresses: &BTreeSet<ExtendedAddr>,
) -> Result<Coin> {
    let mut amount = Coin::zero();

    for output in outputs.iter() {
        if transfer_addresses.contains(&output.address) {
            amount = (amount + output.value).chain(|| {
                (
                    ErrorKind::IllegalInput,
                    "Total output amount exceeded maximum allowed value",
                )
            })?;
        }
    }

    Ok(amount)
}

fn get_total_output_amount(outputs: &[TxOut]) -> Result<Coin> {
    let mut amount = Coin::zero();

    for output in outputs.iter() {
        amount = (amount + output.value).chain(|| {
            (
                ErrorKind::IllegalInput,
                "Total output amount exceeded maximum allowed value",
            )
        })?;
    }

    Ok(amount)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use chain_core::tx::data::attribute::TxAttributes;
    use chain_core::tx::data::Tx;
    use client_common::storage::MemoryStorage;

    use crate::wallet::{DefaultWalletClient, WalletClient};

    fn transfer_transactions(addresses: [ExtendedAddr; 2]) -> [Transaction; 2] {
        let transaction1 = Transaction::TransferTransaction(Tx::new_with(
            Vec::new(),
            vec![TxOut::new(addresses[0].clone(), Coin::new(100).unwrap())],
            TxAttributes::default(),
        ));

        let transaction2 = Transaction::TransferTransaction(Tx::new_with(
            vec![TxoPointer::new(transaction1.id(), 0)],
            vec![TxOut::new(addresses[1].clone(), Coin::new(100).unwrap())],
            TxAttributes::default(),
        ));

        [transaction1, transaction2]
    }

    #[test]
    fn check_transfer_transaction_flow() {
        let storage = MemoryStorage::default();
        let transaction_handler = DefaultTransactionHandler::new(storage.clone());
        let wallet = DefaultWalletClient::new_read_only(storage);

        let name1 = "name1";
        let passphrase1 = &SecUtf8::from("passphrase1");

        let name2 = "name2";
        let passphrase2 = &SecUtf8::from("passphrase2");

        assert!(wallet.new_wallet(name1, passphrase1).is_ok());
        assert!(wallet.new_wallet(name2, passphrase2).is_ok());

        let address1 = wallet.new_transfer_address(name1, passphrase1).unwrap();
        let address2 = wallet.new_transfer_address(name2, passphrase2).unwrap();

        let transactions = transfer_transactions([address1, address2]);

        // Flow for wallet 1

        transaction_handler
            .on_next(
                name1,
                passphrase1,
                transactions[0].clone(),
                0,
                DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
            )
            .unwrap();

        assert_eq!(
            Coin::new(100).unwrap(),
            wallet.balance(name1, passphrase1).unwrap(),
        );

        assert_eq!(1, wallet.history(name1, passphrase1).unwrap().len());

        assert_eq!(
            1,
            wallet
                .unspent_transactions(name1, passphrase1)
                .unwrap()
                .len()
        );

        transaction_handler
            .on_next(
                name1,
                passphrase1,
                transactions[1].clone(),
                1,
                DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
            )
            .unwrap();

        assert_eq!(Coin::zero(), wallet.balance(name1, passphrase1).unwrap());

        assert_eq!(2, wallet.history(name1, passphrase1).unwrap().len());

        assert_eq!(
            0,
            wallet
                .unspent_transactions(name1, passphrase1)
                .unwrap()
                .len()
        );

        // Flow for wallet 2

        transaction_handler
            .on_next(
                name2,
                passphrase2,
                transactions[0].clone(),
                0,
                DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
            )
            .unwrap();

        assert_eq!(
            Coin::new(0).unwrap(),
            wallet.balance(name2, passphrase2).unwrap(),
        );

        assert_eq!(0, wallet.history(name2, passphrase2).unwrap().len());

        assert_eq!(
            0,
            wallet
                .unspent_transactions(name2, passphrase2)
                .unwrap()
                .len()
        );

        transaction_handler
            .on_next(
                name2,
                passphrase2,
                transactions[1].clone(),
                1,
                DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
            )
            .unwrap();

        assert_eq!(
            Coin::new(100).unwrap(),
            wallet.balance(name2, passphrase2).unwrap()
        );

        assert_eq!(1, wallet.history(name2, passphrase2).unwrap().len());

        assert_eq!(
            1,
            wallet
                .unspent_transactions(name2, passphrase2)
                .unwrap()
                .len()
        );
    }
}
