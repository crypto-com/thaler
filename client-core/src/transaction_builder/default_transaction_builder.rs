use failure::ResultExt;
use secstr::SecUtf8;

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::Tx;
use chain_core::tx::fee::FeeAlgorithm;
use chain_core::tx::{TransactionId, TxAux};
use client_common::{ErrorKind, Result};

use crate::{SelectedUnspentTransactions, Signer, TransactionBuilder, UnspentTransactions};

/// Default implementation of `TransactionBuilder`
#[derive(Debug)]
pub struct DefaultTransactionBuilder<S, F>
where
    S: Signer,
    F: FeeAlgorithm,
{
    signer: S,
    fee_algorithm: F,
}

impl<S, F> DefaultTransactionBuilder<S, F>
where
    S: Signer,
    F: FeeAlgorithm,
{
    /// Creates a new instance of transaction builder
    pub fn new(signer: S, fee_algorithm: F) -> Self {
        Self {
            signer,
            fee_algorithm,
        }
    }
}

impl<S, F> TransactionBuilder for DefaultTransactionBuilder<S, F>
where
    S: Signer,
    F: FeeAlgorithm,
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
        let mut fees = Coin::zero();

        loop {
            let (selected_unspent_transactions, difference_amount) =
                unspent_transactions.select(fees)?;

            let transaction = build_transaction(
                &selected_unspent_transactions,
                outputs.clone(),
                attributes.clone(),
                difference_amount,
                return_address.clone(),
            );

            let witness = self.signer.sign(
                name,
                passphrase,
                transaction.id(),
                selected_unspent_transactions,
            )?;

            let tx_aux = TxAux::TransferTx(transaction, witness);

            let new_fees = self
                .fee_algorithm
                .calculate_for_txaux(&tx_aux)
                .context(ErrorKind::BalanceAdditionError)?
                .to_coin();

            if new_fees > fees {
                fees = new_fees;
            } else {
                return Ok(tx_aux);
            }
        }
    }
}

fn build_transaction(
    selected_unspent_transactions: &SelectedUnspentTransactions,
    mut outputs: Vec<TxOut>,
    attributes: TxAttributes,
    difference_amount: Coin,
    return_address: ExtendedAddr,
) -> Tx {
    if difference_amount == Coin::zero() {
        Tx {
            inputs: selected_unspent_transactions
                .iter()
                .map(|(input, _)| input.clone())
                .collect(),
            outputs: outputs.clone(),
            attributes: attributes.clone(),
        }
    } else {
        outputs.push(TxOut::new(return_address.clone(), difference_amount));

        Tx {
            inputs: selected_unspent_transactions
                .iter()
                .map(|(input, _)| input.clone())
                .collect(),
            outputs,
            attributes,
        }
    }
}
