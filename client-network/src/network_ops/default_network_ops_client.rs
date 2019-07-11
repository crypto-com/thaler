use failure::ResultExt;
use parity_codec::Decode;
use secstr::SecUtf8;

use chain_core::init::coin::Coin;
use chain_core::state::account::{
    DepositBondTx, StakedState, StakedStateAddress, StakedStateOpAttributes, StakedStateOpWitness,
    UnbondTx, WithdrawUnbondedTx,
};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::fee::FeeAlgorithm;
use chain_core::tx::{TransactionId, TxAux};
use client_common::tendermint::Client;
use client_common::{Error, ErrorKind, Result};
use client_core::{Signer, UnspentTransactions, WalletClient};

use crate::NetworkOpsClient;

/// Default implementation of `NetworkOpsClient`
pub struct DefaultNetworkOpsClient<'a, W, S, C, F>
where
    W: WalletClient,
    S: Signer,
    C: Client,
    F: FeeAlgorithm,
{
    wallet_client: &'a W,
    signer: &'a S,
    client: &'a C,
    fee_algorithm: &'a F,
}

impl<'a, W, S, C, F> DefaultNetworkOpsClient<'a, W, S, C, F>
where
    W: WalletClient,
    S: Signer,
    C: Client,
    F: FeeAlgorithm,
{
    /// Creates a new instance of `DefaultNetworkOpsClient`
    pub fn new(wallet_client: &'a W, signer: &'a S, client: &'a C, fee_algorithm: &'a F) -> Self {
        Self {
            wallet_client,
            signer,
            client,
            fee_algorithm,
        }
    }

    /// Get account info
    fn get_account(&self, staked_state_address: &[u8]) -> Result<StakedState> {
        self.client
            .query("account", hex::encode(staked_state_address).as_str())
            .map(|x| x.response.value)
            .and_then(|value| match base64::decode(value.as_bytes()) {
                Ok(a) => Ok(a),
                Err(_b) => Err(Error::from(ErrorKind::RpcError)),
            })
            .and_then(|data| match StakedState::decode(&mut data.as_slice()) {
                Some(a) => Ok(a),
                None => Err(Error::from(ErrorKind::RpcError)),
            })
    }

    /// Get staked state info
    fn get_staked_state_account(
        &self,
        to_staked_account: &StakedStateAddress,
    ) -> Result<StakedState> {
        match to_staked_account {
            StakedStateAddress::BasicRedeem(ref a) => self.get_account(&a.0),
        }
    }
}

impl<'a, W, S, C, F> NetworkOpsClient for DefaultNetworkOpsClient<'a, W, S, C, F>
where
    W: WalletClient,
    S: Signer,
    C: Client,
    F: FeeAlgorithm,
{
    fn create_deposit_bonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        inputs: Vec<TxoPointer>,
        to_address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
    ) -> Result<TxAux> {
        let transaction = DepositBondTx::new(inputs.clone(), to_address, attributes);

        let transactions = inputs
            .into_iter()
            .map(|txo_pointer| {
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
        address: &StakedStateAddress,
        value: Coin,
        attributes: StakedStateOpAttributes,
    ) -> Result<TxAux> {
        let staked_state = self.get_staked_state(name, passphrase, address)?;
        let nonce = staked_state.nonce;

        let transaction = UnbondTx::new(value, nonce, attributes);

        let public_key = match address {
            StakedStateAddress::BasicRedeem(ref redeem_address) => self
                .wallet_client
                .find_public_key(name, passphrase, redeem_address)?
                .ok_or_else(|| Error::from(ErrorKind::AddressNotFound))?,
        };
        let private_key = self
            .wallet_client
            .private_key(passphrase, &public_key)?
            .ok_or_else(|| Error::from(ErrorKind::PrivateKeyNotFound))?;

        let signature = private_key
            .sign(transaction.id())
            .map(StakedStateOpWitness::new)?;

        Ok(TxAux::UnbondStakeTx(transaction, signature))
    }

    fn create_withdraw_unbonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        from_address: &StakedStateAddress,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
    ) -> Result<TxAux> {
        let staked_state = self.get_staked_state(name, passphrase, from_address)?;
        let nonce = staked_state.nonce;

        println!("State: {:?}", staked_state);

        let transaction = WithdrawUnbondedTx::new(nonce, outputs, attributes);

        let public_key = match from_address {
            StakedStateAddress::BasicRedeem(ref redeem_address) => self
                .wallet_client
                .find_public_key(name, passphrase, redeem_address)?
                .ok_or_else(|| Error::from(ErrorKind::AddressNotFound))?,
        };
        let private_key = self
            .wallet_client
            .private_key(passphrase, &public_key)?
            .ok_or_else(|| Error::from(ErrorKind::PrivateKeyNotFound))?;

        let signature = private_key
            .sign(transaction.id())
            .map(StakedStateOpWitness::new)?;

        Ok(TxAux::WithdrawUnbondedStakeTx(transaction, signature))
    }

    fn create_withdraw_all_unbonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        from_address: &StakedStateAddress,
        to_address: ExtendedAddr,
        attributes: TxAttributes,
    ) -> Result<TxAux> {
        let staked_state = self.get_staked_state(name, passphrase, from_address)?;

        let temp_output =
            TxOut::new_with_timelock(to_address.clone(), Coin::zero(), staked_state.unbonded_from);

        let temp_transaction = self.create_withdraw_unbonded_stake_transaction(
            name,
            passphrase,
            from_address,
            vec![temp_output],
            attributes.clone(),
        )?;

        let fee = self
            .fee_algorithm
            .calculate_for_txaux(&temp_transaction)
            .context(ErrorKind::BalanceAdditionError)?
            .to_coin();

        let amount = (staked_state.unbonded - fee).context(ErrorKind::BalanceAdditionError)?;
        let output = TxOut::new_with_timelock(to_address, amount, staked_state.unbonded_from);

        self.create_withdraw_unbonded_stake_transaction(
            name,
            passphrase,
            from_address,
            vec![output],
            attributes,
        )
    }

    fn get_staked_state(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: &StakedStateAddress,
    ) -> Result<StakedState> {
        // Verify if `address` belongs to current wallet
        match address {
            StakedStateAddress::BasicRedeem(ref redeem_address) => {
                self.wallet_client
                    .find_public_key(name, passphrase, redeem_address)?;
            }
        }

        self.get_staked_state_account(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::CoinError;
    use chain_core::tx::fee::Fee;
    use chain_tx_validation::witness::verify_tx_recover_address;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::*;
    use client_core::signer::DefaultSigner;
    use client_core::wallet::DefaultWalletClient;
    use client_core::{PrivateKey, PublicKey};

    #[derive(Debug, Default)]
    struct UnitFeeAlgorithm;

    impl FeeAlgorithm for UnitFeeAlgorithm {
        fn calculate_fee(&self, _num_bytes: usize) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::unit()))
        }

        fn calculate_for_txaux(&self, _txaux: &TxAux) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::unit()))
        }
    }

    #[derive(Default, Clone)]
    pub struct MockClient;

    impl Client for MockClient {
        fn genesis(&self) -> Result<Genesis> {
            unreachable!()
        }

        fn status(&self) -> Result<Status> {
            unreachable!()
        }

        fn block(&self, _: u64) -> Result<Block> {
            unreachable!()
        }

        fn block_results(&self, _: u64) -> Result<BlockResults> {
            unreachable!()
        }

        fn broadcast_transaction(&self, _: &[u8]) -> Result<()> {
            unreachable!()
        }

        fn query(&self, _path: &str, _data: &str) -> Result<QueryResult> {
            Ok(QueryResult {
                response: Response {
                    value:
                        "AAAAAAAAAAAAAAAAAAAAAAAAeiLByLEia/aSXAAAAAAADbIhxPV9XTi5aBOcBukTKq+E6N8="
                            .to_string(),
                },
            })
        }
    }

    #[test]
    fn check_create_deposit_bonded_stake_transaction() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();

        wallet_client.new_wallet(name, passphrase).unwrap();

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            &wallet_client,
            &signer,
            &tendermint_client,
            &fee_algorithm,
        );

        let inputs: Vec<TxoPointer> = vec![];
        let to_staked_account = wallet_client.new_staking_address(name, passphrase).unwrap();;

        let attributes = StakedStateOpAttributes::new(0);
        assert!(network_ops_client
            .create_deposit_bonded_stake_transaction(
                name,
                passphrase,
                inputs,
                to_staked_account,
                attributes,
            )
            .is_ok());
    }

    #[test]
    fn check_create_unbond_stake_transaction() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();

        wallet_client.new_wallet(name, passphrase).unwrap();

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            &wallet_client,
            &signer,
            &tendermint_client,
            &fee_algorithm,
        );

        let value = Coin::new(0).unwrap();
        let address = wallet_client.new_staking_address(name, passphrase).unwrap();
        let attributes = StakedStateOpAttributes::new(0);

        assert!(network_ops_client
            .create_unbond_stake_transaction(name, passphrase, &address, value, attributes)
            .is_ok());
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            &wallet_client,
            &signer,
            &tendermint_client,
            &fee_algorithm,
        );

        wallet_client.new_wallet(name, passphrase).unwrap();

        let from_address = wallet_client.new_staking_address(name, passphrase).unwrap();

        let transaction = network_ops_client
            .create_withdraw_unbonded_stake_transaction(
                name,
                passphrase,
                &from_address,
                Vec::new(),
                TxAttributes::new(171),
            )
            .unwrap();

        match transaction {
            TxAux::WithdrawUnbondedStakeTx(transaction, witness) => {
                let id = transaction.id();
                let account_address =
                    verify_tx_recover_address(&witness, &id).expect("Unable to verify transaction");

                assert_eq!(account_address, from_address)
            }
            _ => unreachable!(
                "`create_withdraw_unbonded_stake_transaction()` created invalid transaction type"
            ),
        }
    }

    #[test]
    fn check_withdraw_all_unbonded_stake_transaction() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            &wallet_client,
            &signer,
            &tendermint_client,
            &fee_algorithm,
        );

        wallet_client.new_wallet(name, passphrase).unwrap();

        let from_address = wallet_client.new_staking_address(name, passphrase).unwrap();
        let to_address = ExtendedAddr::OrTree([0; 32]);

        let transaction = network_ops_client
            .create_withdraw_all_unbonded_stake_transaction(
                name,
                passphrase,
                &from_address,
                to_address,
                TxAttributes::new(171),
            )
            .unwrap();

        match transaction {
            TxAux::WithdrawUnbondedStakeTx(transaction, witness) => {
                let id = transaction.id();
                let account_address =
                    verify_tx_recover_address(&witness, &id).expect("Unable to verify transaction");

                let amount = transaction.outputs[0].value;

                assert_eq!(account_address, from_address);
                assert_eq!(amount, Coin::new(2500000000000000000 - 1).unwrap());
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

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();

        let tendermint_client = MockClient::default();
        let network_ops_client = DefaultNetworkOpsClient::new(
            &wallet_client,
            &signer,
            &tendermint_client,
            &fee_algorithm,
        );

        wallet_client.new_wallet(name, passphrase).unwrap();

        assert_eq!(
            ErrorKind::AddressNotFound,
            network_ops_client
                .create_withdraw_unbonded_stake_transaction(
                    name,
                    passphrase,
                    &StakedStateAddress::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                        &PrivateKey::new().unwrap()
                    ))),
                    Vec::new(),
                    TxAttributes::new(171),
                )
                .unwrap_err()
                .kind()
        );
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction_wallet_not_found() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let fee_algorithm = UnitFeeAlgorithm::default();

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();
        let tendermint_client = MockClient::default();

        let network_ops_client = DefaultNetworkOpsClient::new(
            &wallet_client,
            &signer,
            &tendermint_client,
            &fee_algorithm,
        );

        assert_eq!(
            ErrorKind::WalletNotFound,
            network_ops_client
                .create_withdraw_unbonded_stake_transaction(
                    name,
                    passphrase,
                    &StakedStateAddress::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                        &PrivateKey::new().unwrap()
                    ))),
                    Vec::new(),
                    TxAttributes::new(171),
                )
                .unwrap_err()
                .kind()
        );
    }
}
