use failure::ResultExt;
use secstr::SecStr;

use chain_core::init::coin::Coin;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::Tx;
use chain_core::tx::fee::{Fee, FeeAlgorithm};
use chain_core::tx::TxAux;
use client_common::{Error, ErrorKind, Result};

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

        let mut amount_to_transfer = fee.to_coin();
        for output in outputs.iter() {
            amount_to_transfer =
                (amount_to_transfer + output.value).context(ErrorKind::BalanceAdditionError)?;
        }

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

        let transaction = if transferred_amount < amount_to_transfer {
            Err(Error::from(ErrorKind::InsufficientBalance))
        } else if transferred_amount == amount_to_transfer {
            Ok(Tx {
                inputs: selected_unspent_transactions,
                outputs,
                attributes,
            })
        } else {
            let new_address = wallet_client.new_address(name, passphrase)?;
            outputs.push(TxOut::new(
                new_address,
                (transferred_amount - amount_to_transfer)
                    .context(ErrorKind::BalanceAdditionError)?,
            ));

            Ok(Tx {
                inputs: selected_unspent_transactions,
                outputs,
                attributes,
            })
        }?;

        let mut witnesses = Vec::with_capacity(transaction.inputs.len());

        for input in &transaction.inputs {
            let input = wallet_client.output(&input.id, input.index)?;

            match wallet_client.private_key(name, passphrase, &input.address)? {
                None => return Err(ErrorKind::PrivateKeyNotFound.into()),
                Some(private_key) => witnesses.push(private_key.sign(&transaction.id())?),
            }
        }

        Ok(TxAux::new(transaction, witnesses.into()))
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
