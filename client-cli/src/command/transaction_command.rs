use std::str::FromStr;

use chain_core::common::{Timespec, HASH_SIZE_256};
use chain_core::init::network::get_network_id;
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
use hex::decode;
use quest::{ask, text, yesno};
use secstr::SecUtf8;
use structopt::StructOpt;
use unicase::eq_ascii;

use crate::{ask_passphrase, coin_from_str};

#[derive(Debug)]
pub enum TransactionType {
    Transfer,
    Deposit,
    Unbond,
    Withdraw,
    Unjail,
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
        }
    }
}

fn new_transaction<T: WalletClient, N: NetworkOpsClient>(
    wallet_client: &T,
    network_ops_client: &N,
    name: &str,
    transaction_type: &TransactionType,
) -> Result<()> {
    let passphrase = ask_passphrase(None)?;

    let transaction = match transaction_type {
        TransactionType::Transfer => new_transfer_transaction(wallet_client, name, &passphrase),
        TransactionType::Deposit => new_deposit_transaction(network_ops_client, name, &passphrase),
        TransactionType::Unbond => new_unbond_transaction(network_ops_client, name, &passphrase),
        TransactionType::Withdraw => {
            new_withdraw_transaction(wallet_client, network_ops_client, name, &passphrase)
        }
        TransactionType::Unjail => new_unjail_transaction(network_ops_client, name, &passphrase),
    }?;

    wallet_client.broadcast_transaction(&transaction)?;

    Ok(())
}

fn new_withdraw_transaction<T: WalletClient, N: NetworkOpsClient>(
    wallet_client: &T,
    network_ops_client: &N,
    name: &str,
    passphrase: &SecUtf8,
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

    let attributes = TxAttributes::new_with_access(get_network_id(), access_policies);

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
) -> Result<TxAux> {
    let attributes = StakedStateOpAttributes::new(get_network_id());
    let address = ask_staking_address()?;

    ask("Enter amount (in CRO): ");
    let value_str = text().chain(|| (ErrorKind::IoError, "Unable to read amount"))?;
    let value = coin_from_str(&value_str)?;

    network_ops_client.create_unbond_stake_transaction(name, passphrase, address, value, attributes)
}

fn new_deposit_transaction<N: NetworkOpsClient>(
    network_ops_client: &N,
    name: &str,
    passphrase: &SecUtf8,
) -> Result<TxAux> {
    let attributes = StakedStateOpAttributes::new(get_network_id());
    let inputs = ask_inputs()?;
    let to_address = ask_staking_address()?;

    network_ops_client
        .create_deposit_bonded_stake_transaction(name, passphrase, inputs, to_address, attributes)
}

fn new_transfer_transaction<T: WalletClient>(
    wallet_client: &T,
    name: &str,
    passphrase: &SecUtf8,
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

    let attributes = TxAttributes::new_with_access(get_network_id(), access_policies);

    let return_address = wallet_client.new_transfer_address(name, &passphrase)?;

    wallet_client.create_transaction(name, &passphrase, outputs, attributes, None, return_address)
}

fn new_unjail_transaction<N: NetworkOpsClient>(
    network_ops_client: &N,
    name: &str,
    passphrase: &SecUtf8,
) -> Result<TxAux> {
    let attributes = StakedStateOpAttributes::new(get_network_id());
    let address = ask_staking_address()?;

    network_ops_client.create_unjail_transaction(name, passphrase, address, attributes)
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

#[cfg(not(test))]
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

#[cfg(test)]
fn ask_staking_address() -> Result<StakedStateAddress> {
    Ok(
        StakedStateAddress::from_str("0x83fe11feb0887183eb62c30994bdd9e303497e3d")
            .expect("get staked address"),
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use chain_core::init::coin::Coin;
    use chain_core::init::coin::CoinError;

    use chain_core::tx::data::TxId;
    use chain_core::tx::fee::Fee;
    use chain_core::tx::fee::FeeAlgorithm;

    use chain_core::tx::TxAux;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::*;
    use client_common::tendermint::Client;
    use client_common::PrivateKey;
    use client_common::SignedTransaction;
    use client_common::Transaction;
    use client_core::cipher::TransactionObfuscation;
    use client_core::signer::DefaultSigner;
    use client_core::wallet::DefaultWalletClient;
    use client_network::network_ops::DefaultNetworkOpsClient;
    //use parity_scale_codec::codec::Encode;
    struct MockClient;

    impl Client for MockClient {
        fn genesis(&self) -> Result<Genesis> {
            unreachable!()
        }

        fn status(&self) -> Result<Status> {
            unreachable!()
        }

        fn block(&self, _height: u64) -> Result<Block> {
            unreachable!()
        }

        fn block_batch<'a, T: Iterator<Item = &'a u64>>(&self, _heights: T) -> Result<Vec<Block>> {
            unreachable!()
        }

        fn block_results(&self, _height: u64) -> Result<BlockResults> {
            unreachable!()
        }

        fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
            &self,
            _heights: T,
        ) -> Result<Vec<BlockResults>> {
            unreachable!()
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<BroadcastTxResult> {
            Ok(BroadcastTxResult {
                code: 0,
                data: String::from(""),
                hash: String::from(""),
                log: String::from(""),
            })
        }

        fn query(&self, _path: &str, _data: &[u8]) -> Result<QueryResult> {
            unreachable!()
        }
    }

    #[derive(Default)]
    pub struct ZeroFeeAlgorithm;

    impl FeeAlgorithm for ZeroFeeAlgorithm {
        fn calculate_fee(&self, _num_bytes: usize) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::zero()))
        }

        fn calculate_for_txaux(&self, _txaux: &TxAux) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::zero()))
        }
    }

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
            match transaction {
                SignedTransaction::TransferTransaction(_, _) => unreachable!(),
                SignedTransaction::DepositStakeTransaction(_, _) => unreachable!(),
                SignedTransaction::WithdrawUnbondedStakeTransaction(_, _, _) => unreachable!(),
            }
        }
    }

    #[test]
    fn check_unjail_tx() {
        let name = "name";

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let fee_algorithm = ZeroFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());
        let tendermint_client = MockClient {};

        let network_ops_client = DefaultNetworkOpsClient::new(
            DefaultWalletClient::new_read_only(storage.clone()),
            signer,
            tendermint_client,
            fee_algorithm,
            MockTransactionCipher,
        );

        assert!(!new_transaction(
            &wallet_client,
            &network_ops_client,
            name,
            &TransactionType::Unjail,
        )
        .is_ok());
    }
}
