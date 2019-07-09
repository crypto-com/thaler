use failure::ResultExt;
use hex::decode;
use quest::{ask, text, yesno};
use structopt::StructOpt;

use chain_core::common::Timespec;
use chain_core::init::address::CroAddressError;
use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use client_common::{ErrorKind, Result};
use client_core::WalletClient;

use crate::ask_passphrase;

#[derive(Debug, StructOpt)]
pub enum TransactionCommand {
    #[structopt(name = "new", about = "New transaction")]
    New {
        #[structopt(
            name = "chain-id",
            short,
            long,
            help = "Chain ID for transaction (Last two hex digits of chain-id)"
        )]
        chain_id: String,
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
    },
}

impl TransactionCommand {
    pub fn execute<T: WalletClient>(&self, wallet_client: T) -> Result<()> {
        match self {
            TransactionCommand::New { chain_id, name } => {
                Self::new_transaction(wallet_client, name, chain_id)
            }
        }
    }

    fn new_transaction<T: WalletClient>(
        wallet_client: T,
        name: &str,
        chain_id: &str,
    ) -> Result<()> {
        let passphrase = ask_passphrase()?;
        let attributes =
            TxAttributes::new(decode(chain_id).context(ErrorKind::DeserializationError)?[0]);
        let outputs = Self::ask_outputs()?;

        let return_address = wallet_client.new_single_transfer_address(name, &passphrase)?;

        let transaction = wallet_client.create_transaction(
            name,
            &passphrase,
            outputs,
            attributes,
            None,
            return_address,
        )?;

        wallet_client.broadcast_transaction(&transaction)
    }

    fn ask_outputs() -> Result<Vec<TxOut>> {
        let mut outputs = Vec::new();

        let mut flag = true;

        while flag {
            ask("Enter output address: ");
            let address_encoded = text().context(ErrorKind::IoError)?;

            let address = address_encoded
                .parse::<ExtendedAddr>()
                .context(ErrorKind::DeserializationError)?;

            ask("Enter amount: ");
            let amount = text()
                .context(ErrorKind::IoError)?
                .parse::<Coin>()
                .context(ErrorKind::DeserializationError)?;

            ask("Enter timelock (seconds from UNIX epoch) (leave blank if output is not time locked): ");
            let timelock = text().context(ErrorKind::IoError)?;

            if timelock.is_empty() {
                outputs.push(TxOut::new(address, amount));
            } else {
                outputs.push(TxOut::new_with_timelock(
                    address,
                    amount,
                    timelock
                        .parse::<Timespec>()
                        .context(ErrorKind::DeserializationError)?,
                ));
            }

            ask("More outputs? [yN] ");
            match yesno(false).context(ErrorKind::IoError)? {
                None => return Err(ErrorKind::InvalidInput.into()),
                Some(value) => flag = value,
            }
        }

        Ok(outputs)
    }
}
