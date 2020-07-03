use std::collections::BTreeSet;
use std::str::FromStr;

use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

use crate::{rpc_error_from_string, to_rpc_error};
use chain_core::init::coin::Coin;
use chain_core::state::account::{
    ConfidentialInit, CouncilNodeMeta, StakedState, StakedStateAddress, StakedStateOpAttributes,
};
use chain_core::state::tendermint::TendermintValidatorPubKey;
use chain_core::tx::data::access::{TxAccess, TxAccessPolicy};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use client_common::{Error, ErrorKind, PublicKey, Result as CommonResult, ResultExt, Transaction};
use client_core::wallet::WalletRequest;
use client_core::{MultiSigWalletClient, WalletClient};
use client_network::NetworkOpsClient;

#[rpc(server)]
pub trait StakingRpc: Send + Sync {
    #[rpc(name = "staking_depositStake")]
    fn deposit_stake(
        &self,
        request: WalletRequest,
        to_address: String,
        inputs: Vec<TxoPointer>,
    ) -> Result<String>;

    #[rpc(name = "staking_depositAmountStake")]
    fn deposit_amount_stake(
        &self,
        request: WalletRequest,
        to_address: String,
        amount: Coin,
    ) -> Result<String>;

    #[rpc(name = "staking_state")]
    fn state(&self, name: String, address: StakedStateAddress) -> Result<StakedState>;

    #[rpc(name = "staking_unbondStake")]
    fn unbond_stake(
        &self,
        request: WalletRequest,
        staking_address: String,
        amount: Coin,
    ) -> Result<String>;

    #[rpc(name = "staking_withdrawAllUnbondedStake")]
    fn withdraw_all_unbonded_stake(
        &self,
        request: WalletRequest,
        from_address: String,
        to_address: String,
        view_keys: Vec<String>,
    ) -> Result<String>;

    #[rpc(name = "staking_unjail")]
    fn unjail(&self, request: WalletRequest, unjail_address: String) -> Result<String>;

    #[rpc(name = "staking_validatorNodeJoin")]
    fn node_join(
        &self,
        request: WalletRequest,
        validator_node_name: String,
        validator_pubkey: String,
        staking_address: String,
        keypackage: String,
    ) -> Result<String>;
}

pub struct StakingRpcImpl<T, N>
where
    T: WalletClient,
    N: NetworkOpsClient,
{
    client: T,
    ops_client: N,
    network_id: u8,
}

impl<T, N> StakingRpcImpl<T, N>
where
    T: WalletClient,
    N: NetworkOpsClient,
{
    pub fn new(client: T, ops_client: N, network_id: u8) -> Self {
        StakingRpcImpl {
            client,
            ops_client,
            network_id,
        }
    }
}

impl<T, N> StakingRpc for StakingRpcImpl<T, N>
where
    T: WalletClient + MultiSigWalletClient + 'static,
    N: NetworkOpsClient + 'static,
{
    fn deposit_stake(
        &self,
        request: WalletRequest,
        to_address: String,
        inputs: Vec<TxoPointer>,
    ) -> Result<String> {
        let to_address = StakedStateAddress::from_str(&to_address)
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    format!("Unable to deserialize to_address ({})", to_address),
                )
            })
            .map_err(to_rpc_error)?;
        let attributes = StakedStateOpAttributes::new(self.network_id);

        if !self
            .client
            .has_unspent_transactions(&request.name, &request.enckey, &inputs)
            .map_err(to_rpc_error)?
        {
            return Err( rpc_error_from_string("Given transaction inputs are not present in unspent transactions (synchronizing your wallet may help)".into()));
        }

        let transactions = inputs
            .into_iter()
            .map(|txo_pointer| {
                let output = self
                    .client
                    .output(&request.name, &request.enckey, &txo_pointer)
                    .map_err(to_rpc_error)?;
                Ok((txo_pointer, output))
            })
            .collect::<Result<Vec<(TxoPointer, TxOut)>>>()
            .map_err(to_rpc_error)?;

        let (transaction, tx_pending) = self
            .ops_client
            .create_deposit_bonded_stake_transaction(
                &request.name,
                &request.enckey,
                transactions,
                to_address,
                attributes,
                true,
            )
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)?;

        // update the wallet pending transaction state
        self.client
            .update_tx_pending_state(
                &request.name,
                &request.enckey,
                transaction.tx_id(),
                tx_pending,
            )
            .map_err(to_rpc_error)?;

        Ok(hex::encode(transaction.tx_id()))
    }

    /// deposit amount coin to a deposit address
    /// 1. build a transfer transaction to make a UTXO which amount is `deposit_amount + fee`
    /// 2. send to a self created transfer address, waiting it confirmed
    /// 3. use the `outputs[0]` of the transfer transaction to deposit
    /// 4. broadcast the deposit transaction, return tx_id
    fn deposit_amount_stake(
        &self,
        request: WalletRequest,
        to_address: String,
        amount: Coin,
    ) -> Result<String> {
        let to_staking_address = StakedStateAddress::from_str(&to_address)
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    format!("Unable to deserialize to_staking_address ({})", to_address),
                )
            })
            .map_err(to_rpc_error)?;
        let attr = StakedStateOpAttributes::new(self.network_id);
        let fee = self
            .ops_client
            .calculate_deposit_fee()
            .map_err(to_rpc_error)?;
        let total_amount = (amount + fee).map_err(to_rpc_error)?;
        // 1. build a transfer transaction to make a UTXO which amount is `deposit_amount + fee`
        let to_transfer_address = self
            .client
            .new_transfer_address(&request.name, &request.enckey)
            .map_err(to_rpc_error)?;
        let tx_id = self
            .client
            .send_to_address_commit(
                &request.name,
                &request.enckey,
                total_amount,
                to_transfer_address,
                &mut BTreeSet::new(),
                self.network_id,
            )
            .map_err(to_rpc_error)?;

        // 2. use the outputs[0] to deposit
        let transaction = self
            .client
            .get_transaction(&request.name, &request.enckey, tx_id)
            .map_err(to_rpc_error)?;
        let output = match transaction {
            Transaction::TransferTransaction(tx) => {
                if tx.outputs.is_empty() {
                    return Err(rpc_error_from_string("invalid transaction".into()));
                }
                tx.outputs[0].clone()
            }
            _ => return Err(rpc_error_from_string("invalid transaction type".into())),
        };
        let txo_pointer = TxoPointer::new(tx_id, 0);
        let transactions = vec![(txo_pointer, output)];
        let (transaction, tx_pending) = self
            .ops_client
            .create_deposit_bonded_stake_transaction(
                &request.name,
                &request.enckey,
                transactions,
                to_staking_address,
                attr,
                true,
            )
            .map_err(to_rpc_error)?;

        // 4. broadcast the deposit transaction and waiting it confirmed
        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)?;
        // update the wallet pending transaction state
        self.client
            .update_tx_pending_state(
                &request.name,
                &request.enckey,
                transaction.tx_id(),
                tx_pending,
            )
            .map_err(to_rpc_error)?;
        Ok(hex::encode(transaction.tx_id()))
    }

    fn state(&self, name: String, address: StakedStateAddress) -> Result<StakedState> {
        self.ops_client
            .get_staked_state(&name, &address, true)
            .map_err(to_rpc_error)
    }

    fn unbond_stake(
        &self,
        request: WalletRequest,
        staking_address: String,
        amount: Coin,
    ) -> Result<String> {
        let attr = StakedStateOpAttributes::new(self.network_id);
        let addr = StakedStateAddress::from_str(&staking_address)
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    format!(
                        "Unable to deserialize staking address ({})",
                        staking_address
                    ),
                )
            })
            .map_err(to_rpc_error)?;

        let transaction = self
            .ops_client
            .create_unbond_stake_transaction(
                &request.name,
                &request.enckey,
                addr,
                amount,
                attr,
                true,
            )
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)?;

        Ok(hex::encode(transaction.tx_id()))
    }

    fn withdraw_all_unbonded_stake(
        &self,
        request: WalletRequest,
        from_address: String,
        to_address: String,
        view_keys: Vec<String>,
    ) -> Result<String> {
        let from_address = StakedStateAddress::from_str(&from_address)
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    format!("Unable to deserialize from_address ({})", from_address),
                )
            })
            .map_err(to_rpc_error)?;
        let to_address = ExtendedAddr::from_str(&to_address)
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    format!("Unable to deserialize to_address ({})", to_address),
                )
            })
            .map_err(to_rpc_error)?;
        let mut view_keys = view_keys
            .iter()
            .map(|key| PublicKey::from_str(key))
            .collect::<CommonResult<BTreeSet<PublicKey>>>()
            .map_err(to_rpc_error)?;

        let view_key = self
            .client
            .view_key(&request.name, &request.enckey)
            .map_err(to_rpc_error)?;

        view_keys.insert(view_key);

        let access_policies: BTreeSet<_> = view_keys
            .iter()
            .map(|key| TxAccessPolicy {
                view_key: key.into(),
                access: TxAccess::AllData,
            })
            .collect();

        let attributes =
            TxAttributes::new_with_access(self.network_id, access_policies.into_iter().collect());

        let (transaction, tx_pending) = self
            .ops_client
            .create_withdraw_all_unbonded_stake_transaction(
                &request.name,
                &request.enckey,
                &from_address,
                to_address,
                attributes,
                true,
            )
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)?;
        // update the wallet pending transaction state
        self.client
            .update_tx_pending_state(
                &request.name,
                &request.enckey,
                transaction.tx_id(),
                tx_pending,
            )
            .map_err(to_rpc_error)?;
        Ok(hex::encode(transaction.tx_id()))
    }

    fn unjail(&self, request: WalletRequest, unjail_address: String) -> Result<String> {
        let unjail_address = StakedStateAddress::from_str(&unjail_address)
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    format!("Unable to deserialize unjail_address ({})", unjail_address),
                )
            })
            .map_err(to_rpc_error)?;

        let attributes = StakedStateOpAttributes::new(self.network_id);

        let transaction = self
            .ops_client
            .create_unjail_transaction(
                &request.name,
                &request.enckey,
                unjail_address,
                attributes,
                true,
            )
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)?;

        Ok(hex::encode(transaction.tx_id()))
    }

    fn node_join(
        &self,
        request: WalletRequest,
        validator_node_name: String,
        validator_pubkey: String,
        staking_addr: String,
        keypackage: String,
    ) -> Result<String> {
        let attributes = StakedStateOpAttributes::new(self.network_id);
        let staking_account_address = staking_addr
            .parse::<StakedStateAddress>()
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to deserialize staking address",
                )
            })
            .map_err(to_rpc_error)?;
        let node_metadata =
            get_node_metadata(&validator_node_name, &validator_pubkey, &keypackage)?;
        let transaction = self
            .ops_client
            .create_node_join_transaction(
                &request.name,
                &request.enckey,
                staking_account_address,
                attributes,
                node_metadata,
                true,
            )
            .map_err(to_rpc_error)?;
        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)?;

        Ok(hex::encode(transaction.tx_id()))
    }
}

fn get_node_metadata(
    validator_name: &str,
    validator_pubkey: &str,
    keypackage: &str,
) -> Result<CouncilNodeMeta> {
    let decoded_pubkey = base64::decode(validator_pubkey)
        .chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to decode base64 encoded bytes of validator pubkey",
            )
        })
        .map_err(to_rpc_error)?;

    if decoded_pubkey.len() != 32 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Expected validator pubkey of 32 bytes",
        ))
        .map_err(to_rpc_error);
    }

    let mut pubkey_bytes = [0; 32];
    pubkey_bytes.copy_from_slice(&decoded_pubkey);

    let keypackage = base64::decode(keypackage)
        .err_kind(ErrorKind::InvalidInput, || "invalid base64")
        .map_err(to_rpc_error)?;

    Ok(CouncilNodeMeta::new_with_details(
        validator_name.to_string(),
        None,
        TendermintValidatorPubKey::Ed25519(pubkey_bytes),
        ConfidentialInit { keypackage },
    ))
}
