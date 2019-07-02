use crate::NetworkOpsClient;
use chain_core::init::coin::Coin;
use chain_core::state::account::Nonce;
use chain_core::state::account::StakedState;
use chain_core::state::account::{DepositBondTx, UnbondTx};
use chain_core::state::account::{StakedStateAddress, StakedStateOpAttributes};
use chain_core::state::account::{StakedStateOpWitness, WithdrawUnbondedTx};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::{TransactionId, TxAux};
use client_common::tendermint::Client;
use client_common::{Error, ErrorKind, Result};
use client_core::signer::Signer;
use client_core::UnspentTransactions;
use client_core::WalletClient;
use secstr::SecUtf8;
/// Default implementation of `NetworkOpsClient`
pub struct DefaultNetworkOpsClient<'a, W, S, C>
where
    W: WalletClient,
    S: Signer,
    C: Client,
{
    wallet_client: &'a W,
    signer: &'a S,
    client: &'a C,
}

impl<'a, W, S, C> DefaultNetworkOpsClient<'a, W, S, C>
where
    W: WalletClient,
    S: Signer,
    C: Client,
{
    /// Creates a new instance of `DefaultNetworkOpsClient`
    pub fn new(wallet_client: &'a W, signer: &'a S, client: &'a C) -> Self {
        Self {
            wallet_client,
            signer,
            client,
        }
    }
}

impl<'a, W, S, C> NetworkOpsClient for DefaultNetworkOpsClient<'a, W, S, C>
where
    W: WalletClient,
    S: Signer,
    C: Client,
{
    fn get_staked_state_account(
        &self,
        to_staked_account: StakedStateAddress,
    ) -> Result<StakedState> {
        match to_staked_account {
            StakedStateAddress::BasicRedeem(a) => {
                self.client.get_account(&a.0).and_then(|account| {
                    Ok(account)
                })
            }
        }
    }

    fn get_staked_state_nonce(&self, to_staked_account: StakedStateAddress) -> Result<Nonce> {
        let state = self.get_staked_state_account(to_staked_account);
        match state {
            Ok(a) => Ok(a.nonce),
            Err(b) => Err(b),
        }
    }

    fn create_deposit_bonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        inputs: Vec<TxoPointer>,
        to_staked_account: StakedStateAddress,
        attributes: StakedStateOpAttributes,
    ) -> Result<TxAux> {
        let transaction: DepositBondTx =
            DepositBondTx::new(inputs.clone(), to_staked_account, attributes);

        let transactions = inputs
            .into_iter()
            .map(|txo_pointer: TxoPointer| {
                let id = txo_pointer.id;
                let index = txo_pointer.index;
                Ok((txo_pointer, self.wallet_client.output(&id, index as usize)?))
            })
            .collect::<Result<Vec<(TxoPointer, TxOut)>>>()?;
        let unspent_transactions = UnspentTransactions::new(transactions);
        let witness = self.signer.sign(
            name,
            passphrase,
            transaction.id(),
            unspent_transactions.select_all(),
        )?;
        Ok(TxAux::DepositStakeTx(transaction, witness))
    }
    fn create_unbond_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        from_address: &ExtendedAddr,
        value: Coin,
        attributes: StakedStateOpAttributes,
        nonce: Nonce,
    ) -> Result<TxAux> {
        match from_address {
            ExtendedAddr::BasicRedeem(ref redeem_address) => {
                let transaction = UnbondTx::new(value, nonce, attributes);
                let public_key = self
                    .wallet_client
                    .find_public_key(name, passphrase, redeem_address)?
                    .ok_or_else(|| Error::from(ErrorKind::AddressNotFound))?;

                let private_key = self
                    .wallet_client
                    .private_key(passphrase, &public_key)?
                    .ok_or_else(|| Error::from(ErrorKind::PrivateKeyNotFound))?;
                let signature = private_key
                    .sign(transaction.id())
                    .map(StakedStateOpWitness::new)?;
                Ok(TxAux::UnbondStakeTx(transaction, signature))
            }
            ExtendedAddr::OrTree(_) => Err(ErrorKind::InvalidInput.into()),
        }
    }

    fn create_withdraw_unbonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        from_address: &ExtendedAddr,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        nonce: Nonce,
    ) -> Result<TxAux> {
        match from_address {
            ExtendedAddr::BasicRedeem(ref redeem_address) => {
                let transaction = WithdrawUnbondedTx::new(nonce, outputs, attributes);
                let public_key = self
                    .wallet_client
                    .find_public_key(name, passphrase, redeem_address)?
                    .ok_or_else(|| Error::from(ErrorKind::AddressNotFound))?;
                let private_key = self
                    .wallet_client
                    .private_key(passphrase, &public_key)?
                    .ok_or_else(|| Error::from(ErrorKind::PrivateKeyNotFound))?;
                let signature = private_key
                    .sign(transaction.id())
                    .map(StakedStateOpWitness::new)?;
                Ok(TxAux::WithdrawUnbondedStakeTx(transaction, signature))
            }
            ExtendedAddr::OrTree(_) => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chain_core::init::address::RedeemAddress;
    use chain_core::tx::data::address::ExtendedAddr;

    use chain_tx_validation::witness::verify_tx_recover_address;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::RpcClient;
    use client_core::signer::DefaultSigner;
    use client_core::wallet::DefaultWalletClient;
    use client_core::{PrivateKey, PublicKey};
    use std::str::FromStr;

    #[test]
    fn check_create_deposit_bonded_stake_transaction() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");
        let tendermint_url = "http://localhost:26657/";

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();
        let tendermint_client = RpcClient::new(&tendermint_url);
        let network_ops_client =
            DefaultNetworkOpsClient::new(&wallet_client, &signer, &tendermint_client);

        let inputs: Vec<TxoPointer> = vec![];
        let to_staked_account =
            RedeemAddress::from_str("1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap();

        let attributes = StakedStateOpAttributes::new(0);
        assert!(network_ops_client
            .create_deposit_bonded_stake_transaction(
                name,
                passphrase,
                inputs,
                to_staked_account.into(),
                attributes,
            )
            .is_ok());
    }

    #[test]
    fn check_create_unbond_stake_transaction() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");
        let tendermint_url = "http://localhost:26657/";

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();

        let tendermint_client = RpcClient::new(&tendermint_url);

        let network_ops_client =
            DefaultNetworkOpsClient::new(&wallet_client, &signer, &tendermint_client);

        let value = Coin::new(0).unwrap();
        let attributes = StakedStateOpAttributes::new(0);
        let nonce = 0;
        assert_eq!(
            ErrorKind::InvalidInput,
            network_ops_client
                .create_unbond_stake_transaction(
                    name,
                    passphrase,
                    &ExtendedAddr::OrTree([0; 32]),
                    value,
                    attributes,
                    nonce,
                )
                .unwrap_err()
                .kind()
        );
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");
        let tendermint_url = "http://localhost:26657/";
        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();
        let tendermint_client = RpcClient::new(&tendermint_url);

        let network_ops_client =
            DefaultNetworkOpsClient::new(&wallet_client, &signer, &tendermint_client);

        wallet_client.new_wallet(name, passphrase).unwrap();

        let from_address = wallet_client.new_redeem_address(name, passphrase).unwrap();
        let nonce = 0;
        let transaction = network_ops_client
            .create_withdraw_unbonded_stake_transaction(
                name,
                passphrase,
                &from_address,
                Vec::new(),
                TxAttributes::new(171),
                nonce,
            )
            .unwrap();

        match transaction {
            TxAux::WithdrawUnbondedStakeTx(transaction, witness) => {
                let id = transaction.id();
                let account_address =
                    verify_tx_recover_address(&witness, &id).expect("Unable to verify transaction");

                assert_eq!(ExtendedAddr::from(account_address), from_address)
            }
            _ => unreachable!(
                "`create_withdraw_unbonded_stake_transaction()` created invalid transaction type"
            ),
        }
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction_address_not_found() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");
        let tendermint_url = "http://localhost:26657/";

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();

        let tendermint_client = RpcClient::new(&tendermint_url);

        let network_ops_client =
            DefaultNetworkOpsClient::new(&wallet_client, &signer, &tendermint_client);
        let nonce = 0;
        wallet_client.new_wallet(name, passphrase).unwrap();

        assert_eq!(
            ErrorKind::AddressNotFound,
            network_ops_client
                .create_withdraw_unbonded_stake_transaction(
                    name,
                    passphrase,
                    &ExtendedAddr::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                        &PrivateKey::new().unwrap(),
                    ))),
                    Vec::new(),
                    TxAttributes::new(171),
                    nonce,
                )
                .unwrap_err()
                .kind()
        );
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction_wallet_not_found() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");
        let tendermint_url = "http://localhost:26657/";
        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();
        let tendermint_client = RpcClient::new(&tendermint_url);

        let network_ops_client =
            DefaultNetworkOpsClient::new(&wallet_client, &signer, &tendermint_client);
        let nonce = 0;
        assert_eq!(
            ErrorKind::WalletNotFound,
            network_ops_client
                .create_withdraw_unbonded_stake_transaction(
                    name,
                    passphrase,
                    &ExtendedAddr::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                        &PrivateKey::new().unwrap(),
                    ))),
                    Vec::new(),
                    TxAttributes::new(171),
                    nonce,
                )
                .unwrap_err()
                .kind()
        );
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction_invalid_address_type() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");
        let tendermint_url = "http://localhost:26657/";

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();
        let tendermint_client = RpcClient::new(&tendermint_url);

        let network_ops_client =
            DefaultNetworkOpsClient::new(&wallet_client, &signer, &tendermint_client);
        let nonce = 0;
        assert_eq!(
            ErrorKind::InvalidInput,
            network_ops_client
                .create_withdraw_unbonded_stake_transaction(
                    name,
                    passphrase,
                    &ExtendedAddr::OrTree([0; 32]),
                    Vec::new(),
                    TxAttributes::new(171),
                    nonce,
                )
                .unwrap_err()
                .kind()
        );
    }
}
