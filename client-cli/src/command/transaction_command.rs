use std::collections::BTreeSet;
use std::str::FromStr;

use chain_core::common::{Timespec, HASH_SIZE_256};
use chain_core::init::network::get_network_id;
use chain_core::state::account::{CouncilNode, StakedStateAddress, StakedStateOpAttributes};
use chain_core::state::tendermint::TendermintValidatorPubKey;
use chain_core::tx::data::access::{TxAccess, TxAccessPolicy};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::{Error, ErrorKind, PublicKey, Result, ResultExt, SecKey};
use client_core::types::TransactionPending;
use client_core::WalletClient;
use client_network::NetworkOpsClient;
use hex::decode;
use quest::{ask, success, text, yesno};
use structopt::StructOpt;
use unicase::eq_ascii;

use crate::{ask_seckey, coin_from_str};

#[derive(Debug)]
pub enum TransactionType {
    Transfer,
    Deposit,
    Unbond,
    Withdraw,
    Unjail,
    NodeJoin,
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
        } else if eq_ascii(s, "unjail") {
            Ok(TransactionType::Unjail)
        } else if eq_ascii(s, "node-join") {
            Ok(TransactionType::NodeJoin)
        } else {
            Err(ErrorKind::DeserializationError.into())
        }
    }
}

#[derive(Debug, StructOpt)]
pub enum TransactionCommand {
    #[structopt(name = "new", about = "New transaction")]
    New {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
        #[structopt(name = "type", short, long, help = "Type of transaction to create")]
        transaction_type: TransactionType,
    },
    #[structopt(
        name = "export",
        about = "Export a plain transaction by a given transaction id"
    )]
    Export {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
        #[structopt(name = "id", short, long, help = "transaction id")]
        id: String,
    },
    #[structopt(
        name = "import",
        about = "Export a plain transaction by a given transaction id"
    )]
    Import {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
        #[structopt(name = "tx", short, long, help = "base64 encoded plain transaction")]
        tx: String,
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
                name,
                transaction_type,
            } => new_transaction(wallet_client, network_ops_client, name, transaction_type),
            TransactionCommand::Export { name, id } => {
                let enckey = ask_seckey(None)?;
                let tx = wallet_client.export_plain_tx(name, &enckey, id)?;
                success(&tx);
                Ok(())
            }
            TransactionCommand::Import { name, tx } => {
                let enckey = ask_seckey(None)?;
                let imported_amount = wallet_client.import_plain_tx(name, &enckey, tx)?;
                success(format!("import amount: {}", imported_amount).as_str());
                Ok(())
            }
        }
    }
}

fn new_transaction<T: WalletClient, N: NetworkOpsClient>(
    wallet_client: &T,
    network_ops_client: &N,
    name: &str,
    transaction_type: &TransactionType,
) -> Result<()> {
    let enckey = ask_seckey(None)?;

    match transaction_type {
        TransactionType::Transfer => {
            let (tx_aux, tx_pending) = new_transfer_transaction(wallet_client, name, &enckey)?;
            wallet_client.broadcast_transaction(&tx_aux)?;
            wallet_client.update_tx_pending_state(&name, &enckey, tx_aux.tx_id(), tx_pending)?;
        }
        TransactionType::Deposit => {
            let tx_aux = new_deposit_transaction(network_ops_client, name, &enckey)?;
            wallet_client.broadcast_transaction(&tx_aux)?;
        }
        TransactionType::Unbond => {
            let tx_aux = new_unbond_transaction(network_ops_client, name, &enckey)?;
            wallet_client.broadcast_transaction(&tx_aux)?;
        }
        TransactionType::Withdraw => {
            let (tx_aux, tx_pending) =
                new_withdraw_transaction(wallet_client, network_ops_client, name, &enckey)?;
            wallet_client.broadcast_transaction(&tx_aux)?;
            wallet_client.update_tx_pending_state(&name, &enckey, tx_aux.tx_id(), tx_pending)?;
        }
        TransactionType::Unjail => {
            let tx_aux = new_unjail_transaction(network_ops_client, name, &enckey)?;
            wallet_client.broadcast_transaction(&tx_aux)?;
        }
        TransactionType::NodeJoin => {
            let tx_aux = new_node_join_transaction(network_ops_client, name, &enckey)?;
            wallet_client.broadcast_transaction(&tx_aux)?;
        }
    };
    Ok(())
}

fn new_withdraw_transaction<T: WalletClient, N: NetworkOpsClient>(
    wallet_client: &T,
    network_ops_client: &N,
    name: &str,
    enckey: &SecKey,
) -> Result<(TxAux, TransactionPending)> {
    let from_address = ask_staking_address()?;
    let to_address = ask_transfer_address()?;
    let view_keys = ask_view_keys()?;

    let self_view_key = wallet_client.view_key(name, enckey)?;

    let mut access_policies = BTreeSet::new();
    access_policies.insert(TxAccessPolicy {
        view_key: self_view_key.into(),
        access: TxAccess::AllData,
    });

    for key in view_keys.iter() {
        access_policies.insert(TxAccessPolicy {
            view_key: key.into(),
            access: TxAccess::AllData,
        });
    }

    let attributes =
        TxAttributes::new_with_access(get_network_id(), access_policies.into_iter().collect());

    network_ops_client.create_withdraw_all_unbonded_stake_transaction(
        name,
        &enckey,
        &from_address,
        to_address,
        attributes,
    )
}

fn new_unbond_transaction<N: NetworkOpsClient>(
    network_ops_client: &N,
    name: &str,
    enckey: &SecKey,
) -> Result<TxAux> {
    let attributes = StakedStateOpAttributes::new(get_network_id());
    let address = ask_staking_address()?;

    ask("Enter amount (in CRO): ");
    let value_str = text().chain(|| (ErrorKind::IoError, "Unable to read amount"))?;
    let value = coin_from_str(&value_str)?;

    network_ops_client.create_unbond_stake_transaction(name, enckey, address, value, attributes)
}

fn new_deposit_transaction<N: NetworkOpsClient>(
    network_ops_client: &N,
    name: &str,
    enckey: &SecKey,
) -> Result<TxAux> {
    let attributes = StakedStateOpAttributes::new(get_network_id());
    let inputs = ask_inputs()?;
    let to_address = ask_staking_address()?;

    network_ops_client
        .create_deposit_bonded_stake_transaction(name, enckey, inputs, to_address, attributes)
}

fn new_transfer_transaction<T: WalletClient>(
    wallet_client: &T,
    name: &str,
    enckey: &SecKey,
) -> Result<(TxAux, TransactionPending)> {
    let outputs = ask_outputs()?;
    let view_keys = ask_view_keys()?;

    let self_view_key = wallet_client.view_key(name, enckey)?;

    let mut access_policies = BTreeSet::new();
    access_policies.insert(TxAccessPolicy {
        view_key: self_view_key.into(),
        access: TxAccess::AllData,
    });

    for key in view_keys.iter() {
        access_policies.insert(TxAccessPolicy {
            view_key: key.into(),
            access: TxAccess::AllData,
        });
    }

    let attributes =
        TxAttributes::new_with_access(get_network_id(), access_policies.into_iter().collect());

    let return_address = wallet_client.new_transfer_address(name, &enckey)?;

    let (transaction, used_inputs, return_amount) = wallet_client.create_transaction(
        name,
        &enckey,
        outputs,
        attributes,
        None,
        return_address,
    )?;
    let tx_pending = TransactionPending {
        block_height: wallet_client.get_current_block_height()?,
        used_inputs,
        return_amount,
    };
    Ok((transaction, tx_pending))
}

fn new_unjail_transaction<N: NetworkOpsClient>(
    network_ops_client: &N,
    name: &str,
    enckey: &SecKey,
) -> Result<TxAux> {
    let attributes = StakedStateOpAttributes::new(get_network_id());
    let address = ask_staking_address()?;

    network_ops_client.create_unjail_transaction(name, enckey, address, attributes)
}

fn new_node_join_transaction<N: NetworkOpsClient>(
    network_ops_client: &N,
    name: &str,
    enckey: &SecKey,
) -> Result<TxAux> {
    let attributes = StakedStateOpAttributes::new(get_network_id());
    let staking_account_address = ask_staking_address()?;
    let node_metadata = ask_node_metadata()?;

    network_ops_client.create_node_join_transaction(
        name,
        enckey,
        staking_account_address,
        attributes,
        node_metadata,
    )
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

        ask("Enter amount (in CRO): ");
        let amount_str = text().chain(|| (ErrorKind::IoError, "Unable to read amount"))?;
        let amount = coin_from_str(&amount_str)?;

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

fn ask_node_metadata() -> Result<CouncilNode> {
    ask("Enter validator node name: ");
    let name = text().chain(|| (ErrorKind::IoError, "Unable to read validator node name"))?;

    ask("Enter validator pub-key (base64 encoded): ");
    let validator_pubkey =
        text().chain(|| (ErrorKind::IoError, "Unable to read validator pub-key"))?;

    let decoded_pubkey = base64::decode(&validator_pubkey).chain(|| {
        (
            ErrorKind::DeserializationError,
            "Unable to decode base64 encoded bytes of validator pub-key",
        )
    })?;

    if decoded_pubkey.len() != 32 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Expected validator pub-key of 32 bytes",
        ));
    }

    let mut pubkey_bytes = [0; 32];
    pubkey_bytes.copy_from_slice(&decoded_pubkey);

    Ok(CouncilNode {
        name,
        security_contact: None,
        consensus_pubkey: TendermintValidatorPubKey::Ed25519(pubkey_bytes),
    })
}
