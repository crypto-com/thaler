use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use serde::{Deserialize, Serialize, Serializer};

use chain_core::tx::data::access::{TxAccess, TxAccessPolicy};
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::TransactionId;
use client_common::PublicKey;

#[derive(Debug, Serialize, Deserialize)]
pub struct RawTransaction {
    tx: Tx,
    #[serde(serialize_with = "serialize_transaction_id")]
    tx_id: TxId,
}

fn serialize_transaction_id<S>(
    transaction_id: &TxId,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(transaction_id))
}

#[rpc]
pub trait TransactionRpc: Send + Sync {
    #[rpc(name = "transaction_createRaw")]
    fn create_raw(
        &self,
        inputs: Vec<TxoPointer>,
        outputs: Vec<TxOut>,
        view_keys: Vec<PublicKey>,
    ) -> Result<RawTransaction>;
}

pub struct TransactionRpcImpl {
    network_id: u8,
}

impl TransactionRpcImpl {
    pub fn new(network_id: u8) -> Self {
        TransactionRpcImpl { network_id }
    }
}

impl TransactionRpc for TransactionRpcImpl {
    fn create_raw(
        &self,
        inputs: Vec<TxoPointer>,
        outputs: Vec<TxOut>,
        view_keys: Vec<PublicKey>,
    ) -> Result<RawTransaction> {
        let mut access_policies: Vec<TxAccessPolicy> = vec![];

        for key in view_keys.iter() {
            access_policies.push(TxAccessPolicy {
                view_key: key.into(),
                access: TxAccess::AllData,
            });
        }

        let attributes = TxAttributes::new_with_access(self.network_id, access_policies);

        let tx = Tx {
            inputs,
            outputs,
            attributes,
        };
        let tx_id = tx.id();

        Ok(RawTransaction { tx, tx_id })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chain_core::init::address::CroAddress;
    use chain_core::init::coin::Coin;
    use chain_core::tx::data::address::ExtendedAddr;
    use client_common::PrivateKey;

    #[test]
    fn create_raw_flow() {
        let chain_id = hex::decode("AB").unwrap()[0];
        let transaction_rpc = TransactionRpcImpl::new(chain_id);

        let inputs = vec![TxoPointer::new([0; 32], 0), TxoPointer::new([1; 32], 0)];

        let outputs = vec![TxOut::new(
            ExtendedAddr::from_cro(
                "dcro1zz30nheum6vnug3mjs0j4kw4w739tca8cuqae2kdjmt8suhv693qcs3qyn",
            )
            .unwrap(),
            Coin::new(750).unwrap(),
        )];

        let view_key_1 = PublicKey::from(&PrivateKey::new().unwrap());
        let view_key_2 = PublicKey::from(&PrivateKey::new().unwrap());
        println!("view_key: {}", view_key_1.to_string());
        let view_keys = vec![view_key_1.clone(), view_key_2.clone()];

        let raw_transaction = transaction_rpc
            .create_raw(inputs.clone(), outputs.clone(), view_keys.clone())
            .expect("create_raw does not work for valid parameters");

        assert_eq!(
            raw_transaction.tx.inputs, inputs,
            "Returned raw transaction should have same inputs from parameter"
        );
        assert_eq!(
            raw_transaction.tx.outputs, outputs,
            "Returned raw transaction should have same outputs from parameter"
        );

        assert_eq!(
            raw_transaction.tx.attributes.chain_hex_id, chain_id,
            "Returned raw transaction should have same chain_id as network"
        );
        assert_eq!(
            raw_transaction.tx.attributes.allowed_view.len(),
            2,
            "Returned raw transaction should have all view_keys from parameter"
        );
        assert_eq!(
            raw_transaction.tx.attributes.allowed_view[0],
            TxAccessPolicy {
                view_key: view_key_1.into(),
                access: TxAccess::AllData,
            },
            "Returned raw transaction should have the same view key from parameter"
        );
        assert_eq!(
            raw_transaction.tx.attributes.allowed_view[1],
            TxAccessPolicy {
                view_key: view_key_2.into(),
                access: TxAccess::AllData,
            },
            "Returned raw transaction should have the same view key from parameter"
        );
    }
}
