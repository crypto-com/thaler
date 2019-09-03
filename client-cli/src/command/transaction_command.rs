use std::str::FromStr;

use hex::decode;
use quest::{ask, text, yesno};
use secstr::SecUtf8;
use structopt::StructOpt;
use unicase::eq_ascii;

use chain_core::common::{Timespec, HASH_SIZE_256};
use chain_core::init::coin::Coin;
use chain_core::state::account::{StakedStateAddress, StakedStateOpAttributes};
use chain_core::tx::data::access::{TxAccess, TxAccessPolicy};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::{Error, ErrorKind, PublicKey, Result, ResultExt};
use client_core::WalletClient;
use client_network::NetworkOpsClient;

use crate::ask_passphrase;

#[derive(Debug)]
pub enum TransactionType {
    Transfer,
    Deposit,
    Unbond,
    Withdraw,
}

impl FromStr for TransactionType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if eq_ascii(s, "transfer") {
            Ok(TransactionType::Transfer)
        } else if eq_ascii(s, "deposit") {
            Ok(TransactionType::Deposit)
        } else if eq_ascii(s, "unbond") {
            Ok(TransactionType::Unbond)
        } else if eq_ascii(s, "withdraw") {
            Ok(TransactionType::Withdraw)
        } else {
            Err(ErrorKind::DeserializationError.into())
        }
    }
}

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
        #[structopt(name = "type", short, long, help = "Type of transaction to create")]
        transaction_type: TransactionType,
    },
}

impl TransactionCommand {
    pub fn execute<T: WalletClient, N: NetworkOpsClient>(
        &self,
        wallet_client: &T,
        network_ops_client: &N,
    ) -> Result<()> {
        match self {
            TransactionCommand::New {
                chain_id,
                name,
                transaction_type,
            } => new_transaction(
                wallet_client,
                network_ops_client,
                name,
                chain_id,
                transaction_type,
            ),
        }
    }
}

fn new_transaction<T: WalletClient, N: NetworkOpsClient>(
    wallet_client: &T,
    network_ops_client: &N,
    name: &str,
    chain_id: &str,
    transaction_type: &TransactionType,
) -> Result<()> {
    let passphrase = ask_passphrase(None)?;

    let transaction = match transaction_type {
        TransactionType::Transfer => {
            new_transfer_transaction(wallet_client, name, &passphrase, chain_id)
        }
        TransactionType::Deposit => {
            new_deposit_transaction(network_ops_client, name, &passphrase, chain_id)
        }
        TransactionType::Unbond => {
            new_unbond_transaction(network_ops_client, name, &passphrase, chain_id)
        }
        TransactionType::Withdraw => new_withdraw_transaction(
            wallet_client,
            network_ops_client,
            name,
            &passphrase,
            chain_id,
        ),
    }?;

    wallet_client.broadcast_transaction(&transaction)?;

    Ok(())
}

fn new_withdraw_transaction<T: WalletClient, N: NetworkOpsClient>(
    wallet_client: &T,
    network_ops_client: &N,
    name: &str,
    passphrase: &SecUtf8,
    chain_id: &str,
) -> Result<TxAux> {
    let from_address = ask_staking_address()?;
    let to_address = ask_transfer_address()?;
    let view_keys = ask_view_keys()?;

    let self_view_key = wallet_client.view_key(name, passphrase)?;

    let mut access_policies = vec![TxAccessPolicy {
        view_key: self_view_key.into(),
        access: TxAccess::AllData,
    }];

    for key in view_keys.iter() {
        access_policies.push(TxAccessPolicy {
            view_key: key.into(),
            access: TxAccess::AllData,
        });
    }

    let attributes = TxAttributes::new_with_access(
        decode(chain_id).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize chain ID",
            )
        })?[0],
        access_policies,
    );

    network_ops_client.create_withdraw_all_unbonded_stake_transaction(
        name,
        &passphrase,
        &from_address,
        to_address,
        attributes,
    )
}

fn new_unbond_transaction<N: NetworkOpsClient>(
    network_ops_client: &N,
    name: &str,
    passphrase: &SecUtf8,
    chain_id: &str,
) -> Result<TxAux> {
    let attributes = StakedStateOpAttributes::new(
        decode(chain_id).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize chain ID",
            )
        })?[0],
    );
    let address = ask_staking_address()?;

    ask("Enter amount: ");
    let value = text()
        .chain(|| (ErrorKind::IoError, "Unable to read amount"))?
        .parse::<Coin>()
        .chain(|| (ErrorKind::DeserializationError, "Unable to parse amount"))?;

    network_ops_client
        .create_unbond_stake_transaction(name, passphrase, &address, value, attributes)
}

fn new_deposit_transaction<N: NetworkOpsClient>(
    network_ops_client: &N,
    name: &str,
    passphrase: &SecUtf8,
    chain_id: &str,
) -> Result<TxAux> {
    let attributes = StakedStateOpAttributes::new(
        decode(chain_id).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize chain ID",
            )
        })?[0],
    );
    let inputs = ask_inputs()?;
    let to_address = ask_staking_address()?;

    network_ops_client
        .create_deposit_bonded_stake_transaction(name, passphrase, inputs, to_address, attributes)
}

fn new_transfer_transaction<T: WalletClient>(
    wallet_client: &T,
    name: &str,
    passphrase: &SecUtf8,
    chain_id: &str,
) -> Result<TxAux> {
    let outputs = ask_outputs()?;
    let view_keys = ask_view_keys()?;

    let self_view_key = wallet_client.view_key(name, passphrase)?;

    let mut access_policies = vec![TxAccessPolicy {
        view_key: self_view_key.into(),
        access: TxAccess::AllData,
    }];

    for key in view_keys.iter() {
        access_policies.push(TxAccessPolicy {
            view_key: key.into(),
            access: TxAccess::AllData,
        });
    }

    let attributes = TxAttributes::new_with_access(
        decode(chain_id).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize chain ID",
            )
        })?[0],
        access_policies,
    );

    let return_address = wallet_client.new_transfer_address(name, &passphrase)?;

    wallet_client.create_transaction(name, &passphrase, outputs, attributes, None, return_address)
}

fn ask_view_keys() -> Result<Vec<PublicKey>> {
    ask(
        "Enter view keys (comma separated) (leave blank if you don't want any additional view keys in transaction): ",
    );

    let view_keys_str = text().chain(|| (ErrorKind::IoError, "Unable to read view keys"))?;

    if view_keys_str.is_empty() {
        Ok(Vec::new())
    } else {
        view_keys_str
            .split(',')
            .map(|view_key| {
                let view_key = view_key.trim();
                PublicKey::from_str(view_key)
            })
            .collect::<Result<Vec<PublicKey>>>()
    }
}

fn ask_outputs() -> Result<Vec<TxOut>> {
    let mut outputs = Vec::new();

    let mut flag = true;

    while flag {
        ask("Enter output address: ");
        let address_encoded =
            text().chain(|| (ErrorKind::IoError, "Unable to read output address"))?;

        let address = address_encoded.parse::<ExtendedAddr>().chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to parse output address",
            )
        })?;

        ask("Enter amount: ");
        let amount = text()
            .chain(|| (ErrorKind::IoError, "Unable to read amount"))?
            .parse::<Coin>()
            .chain(|| (ErrorKind::DeserializationError, "Unable to parse amount"))?;

        ask(
            "Enter timelock (seconds from UNIX epoch) (leave blank if output is not time locked): ",
        );
        let timelock = text().chain(|| (ErrorKind::IoError, "Unable to read timelock value"))?;

        if timelock.is_empty() {
            outputs.push(TxOut::new(address, amount));
        } else {
            outputs.push(TxOut::new_with_timelock(
                address,
                amount,
                timelock.parse::<Timespec>().chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to parse timelock into integer",
                    )
                })?,
            ));
        }

        ask("More outputs? [yN] ");
        match yesno(false).chain(|| (ErrorKind::IoError, "Unable to read yes/no"))? {
            None => return Err(ErrorKind::InvalidInput.into()),
            Some(value) => flag = value,
        }
    }

    Ok(outputs)
}

fn ask_inputs() -> Result<Vec<TxoPointer>> {
    let mut inputs = Vec::new();

    let mut flag = true;

    while flag {
        ask("Enter input transaction ID: ");
        let transaction_id_encoded =
            text().chain(|| (ErrorKind::IoError, "Unable to read transaction ID"))?;

        let transaction_id_decoded = decode(&transaction_id_encoded).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize transaction ID from bytes",
            )
        })?;

        if transaction_id_decoded.len() != HASH_SIZE_256 {
            return Err(Error::new(
                ErrorKind::DeserializationError,
                "Transaction ID should be of 32 bytes",
            ));
        }

        let mut transaction_id: [u8; HASH_SIZE_256] = [0; HASH_SIZE_256];
        transaction_id.copy_from_slice(&transaction_id_decoded);

        ask("Enter input index: ");
        let index = text()
            .chain(|| (ErrorKind::IoError, "Unable to read input index"))?
            .parse::<usize>()
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to parse input index into integer",
                )
            })?;

        inputs.push(TxoPointer::new(transaction_id, index));

        ask("More inputs? [yN] ");
        match yesno(false).chain(|| (ErrorKind::IoError, "Unable to read yes/no"))? {
            None => return Err(ErrorKind::InvalidInput.into()),
            Some(value) => flag = value,
        }
    }

    Ok(inputs)
}

fn ask_staking_address() -> Result<StakedStateAddress> {
    ask("Enter staking address: ");
    let address = text()
        .chain(|| (ErrorKind::IoError, "Unable to read staking address"))?
        .parse::<StakedStateAddress>()
        .chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize staking address",
            )
        })?;

    Ok(address)
}

fn ask_transfer_address() -> Result<ExtendedAddr> {
    ask("Enter transfer address: ");
    let address = text()
        .chain(|| (ErrorKind::IoError, "Unable to read transfer address"))?
        .parse::<ExtendedAddr>()
        .chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize transfer address",
            )
        })?;

    Ok(address)
}
