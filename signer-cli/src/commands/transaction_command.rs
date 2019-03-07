use failure::{format_err, Error, ResultExt};
use hex::{decode, encode};
use quest::{ask, choose, success, text, yesno};
use serde_cbor::ser::to_vec_packed;
use structopt::StructOpt;

use chain_core::common::Timespec;
use chain_core::init::coin::Coin;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::Tx;
use chain_core::tx::TxAux;
use signer_core::{
    get_transaction_witnesses, verify_redeem_address, verify_transaction_id, verify_tree_address,
    SecretsService, SignatureType,
};

use crate::commands::AddressCommand;

/// Enum used to specify different subcommands under transaction command.
/// Refer to main documentation for more details.
#[derive(Debug, StructOpt)]
pub enum TransactionCommand {
    /// Used to generate a new transaction
    #[structopt(name = "generate", about = "Generate new transaction")]
    Generate {
        #[structopt(
            name = "chain-id",
            short,
            long,
            help = "Chain ID for transaction (Last two hex digits of chain-id)"
        )]
        chain_id: String,
        #[structopt(name = "name", short, long, help = "Name of signer")]
        name: String,
    },
}

impl TransactionCommand {
    /// Executes current transaction command
    pub fn execute(&self, service: &SecretsService) -> Result<(), Error> {
        use TransactionCommand::*;

        match self {
            Generate { chain_id, name } => Self::generate(chain_id, name, service),
        }
    }

    /// Takes transaction inputs from user
    fn ask_transaction_inputs(transaction: &mut Tx) -> Result<Vec<SignatureType>, Error> {
        let mut flag = true;

        let signature_types = &["ECDSA", "Schnorr"];
        let mut required_signature_types = Vec::new();

        while flag {
            ask("Enter input transaction ID: ");
            let transaction_id = verify_transaction_id(text()?)?;

            ask("Enter index: ");
            let index = text()?
                .parse::<usize>()
                .context("Unable to parse to usize")?;

            ask("Signature type: \n");
            let signature_type = choose(Default::default(), signature_types)?;

            use SignatureType::*;

            required_signature_types.push(match signature_types[signature_type] {
                "ECDSA" => ECDSA,
                "Schnorr" => Schnorr,
                _ => unreachable!(),
            });

            transaction.add_input(TxoPointer::new(transaction_id, index));

            ask("More inputs? [yN] ");
            match yesno(false)? {
                None => Err(format_err!("Invalid response!"))?,
                Some(value) => flag = value,
            }
        }

        Ok(required_signature_types)
    }

    /// Takes transaction outputs from user
    fn ask_transaction_outputs(transaction: &mut Tx) -> Result<(), Error> {
        let mut flag = true;

        let address_types = &["Redeem", "Tree"];

        while flag {
            ask("Enter output address: ");
            let address = text()?;

            ask("Address type: \n");
            let address = match address_types[choose(Default::default(), address_types)?] {
                "Redeem" => verify_redeem_address(address)?,
                "Tree" => verify_tree_address(address)?,
                _ => unreachable!(),
            };

            ask("Enter amount: ");
            let amount = text()?.parse::<Coin>()?;

            ask("Enter timelock (seconds from UNIX epoch) (leave blank if output is not time locked): ");
            let timelock = text()?;

            if timelock.is_empty() {
                transaction.add_output(TxOut::new(address, amount));
            } else {
                transaction.add_output(TxOut::new_with_timelock(
                    address,
                    amount,
                    timelock.parse::<Timespec>()?,
                ));
            }

            ask("More outputs? [yN] ");
            match yesno(false)? {
                None => Err(format_err!("Invalid response!"))?,
                Some(value) => flag = value,
            }
        }

        Ok(())
    }

    /// Generates new transaction
    fn generate(chain_id: &str, name: &str, service: &SecretsService) -> Result<(), Error> {
        let secrets = AddressCommand::get_secrets(name, service)?;

        let mut transaction = Tx::new();
        transaction.attributes = TxAttributes::new(decode(chain_id)?[0]);

        let required_signature_types = Self::ask_transaction_inputs(&mut transaction)?;

        Self::ask_transaction_outputs(&mut transaction)?;

        let witnesses =
            get_transaction_witnesses(&transaction, &secrets, &required_signature_types)?;

        let txa = TxAux::new(transaction, witnesses);

        ask("Transaction ID: ");
        success(&encode(&txa.tx.id()).to_string());

        ask("Transaction: ");
        success(&encode(&to_vec_packed(&txa)?).to_string());

        Ok(())
    }
}
