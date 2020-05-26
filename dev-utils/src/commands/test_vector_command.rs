use parity_scale_codec::Encode;
use serde::Serialize;

use chain_core::common::Proof;
use chain_core::init::address::{CroAddress, RedeemAddress};
use chain_core::init::coin::Coin;
use chain_core::init::network::Network;
use chain_core::state::account::{
    ConfidentialInit, CouncilNode, DepositBondTx, StakedStateAddress, StakedStateOpAttributes,
    StakedStateOpWitness, UnbondTx, WithdrawUnbondedTx,
};
use chain_core::state::tendermint::TendermintValidatorPubKey;
use chain_core::state::validator::NodeJoinRequestTx;
use chain_core::tx::data::access::{TxAccess, TxAccessPolicy};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::witness::tree::RawXOnlyPubkey;
use chain_core::tx::witness::{TxInWitness, TxWitness};
use chain_core::tx::TransactionId;
use chain_core::tx::{PlainTxAux, TxAux, TxPublicAux};
use client_common::key::PrivateKeyAction;
use client_common::{MultiSigAddress, PrivateKey, PublicKey, Result, Transaction};
use client_core::service::{HDAccountType, HdKey};
use client_core::HDSeed;
use secp256k1::Secp256k1;
use secp256k1::{key::XOnlyPublicKey, SecretKey};

#[derive(Debug)]
pub struct TestVectorCommand {
    network: Network,
    seed: Vec<u8>,
}

impl TestVectorCommand {
    pub fn new(network: String, seed: String) -> Self {
        let network = if network == "devnet" {
            Network::Devnet
        } else if network == "testnet" {
            Network::Testnet
        } else if network == "mainnet" {
            Network::Mainnet
        } else {
            unreachable!()
        };
        let seed = hex::decode(&seed).expect("invali seed");
        Self { network, seed }
    }

    pub fn execute(&self) -> Result<()> {
        let mut vector_factory = VectorFactory::new(self.network, self.seed.clone());
        vector_factory.create_test_vectors()
    }
}

#[derive(Debug, Serialize)]
struct WithdrawUnboundedVector {
    from_address: String,
    to_address: String,
    coin_amount: String,
    witness: String,
    plain_tx_aux: String,
    tx_id: String,
    view_keys: Vec<String>,
}

#[derive(Debug, Serialize)]
struct TransferVector {
    to_address: String,
    return_address: String,
    transfer_amount: String,
    return_amount: String,
    inputs: Vec<String>,
    outputs: Vec<String>,
    witness: String,
    plain_tx_aux: String,
    tx_id: String,
}

#[derive(Debug, Serialize)]
struct DepositStakeVector {
    staking_address: String,
    witness: String,
    transaction: String,
    tx_id: String,
}

#[derive(Debug, Serialize)]
struct NodeJoinVector {
    staking_address: String,
    tendermint_validator_pubkey: String,
    witness: String,
    tx: String,
    tx_id: String,
}

#[derive(Debug, Serialize)]
struct UnboundedStakeVector {
    staking_address: String,
    witness: String,
    tx: String,
    tx_id: String,
}

#[derive(Default, Debug, Serialize)]
struct TestVectors {
    wallet_view_key: Option<String>,
    withdraw_unbonded_vector: Option<WithdrawUnboundedVector>,
    transfer_vector: Option<TransferVector>,
    deposit_stake_vector: Option<DepositStakeVector>,
    nodejoin_vector: Option<NodeJoinVector>,
    unbonded_stake_vector: Option<UnboundedStakeVector>,
}

struct TestVectorWallet {
    hd_key: HdKey,
    view_key: (PublicKey, PrivateKey),
    transfer_addresses: Vec<(ExtendedAddr, PublicKey, PrivateKey)>,
    staking_address: Option<(StakedStateAddress, PublicKey, PrivateKey)>,
}

impl TestVectorWallet {
    pub fn create_keypair(
        &self,
        network: Network,
        account_type: HDAccountType,
    ) -> (PublicKey, PrivateKey) {
        let index = match account_type {
            HDAccountType::Transfer => self.hd_key.transfer_index,
            HDAccountType::Staking => self.hd_key.staking_index,
            HDAccountType::Viewkey => self.hd_key.viewkey_index,
        };
        self.hd_key
            .seed
            .derive_key_pair(network, account_type.index(), index)
            .unwrap()
    }

    pub fn create_transfer_address(
        &mut self,
        network: Network,
    ) -> Result<(ExtendedAddr, PublicKey, PrivateKey)> {
        let (pub_key, priv_key) = self.create_keypair(network, HDAccountType::Transfer);
        self.hd_key.transfer_index += 1;
        let public_keys = vec![pub_key.clone()];
        let multi_sig_address = MultiSigAddress::new(public_keys, pub_key.clone(), 1)?;
        let address_info = (multi_sig_address.into(), pub_key, priv_key);
        self.transfer_addresses.push(address_info.clone());
        Ok(address_info)
    }

    pub fn create_staking_address(&mut self, network: Network) {
        let (pub_key, priv_key) = self.create_keypair(network, HDAccountType::Staking);
        self.hd_key.staking_index += 1;
        let addr = StakedStateAddress::from(RedeemAddress::from(&pub_key));
        self.staking_address = Some((addr, pub_key, priv_key));
    }

    pub fn gen_proof(public_key: PublicKey) -> Result<Option<Proof<RawXOnlyPubkey>>> {
        let public_keys = vec![public_key.clone()];
        let multi_sig_address = MultiSigAddress::new(public_keys.clone(), public_key, 1)?;
        multi_sig_address.generate_proof(public_keys)
    }
}

pub struct VectorFactory {
    network: Network,
    chain_hex_id: u8,
    wallet: TestVectorWallet,
    test_vectors: TestVectors,
}

impl VectorFactory {
    pub fn new(network: Network, seed: Vec<u8>) -> Self {
        let hd_seed = HDSeed { bytes: seed };
        let hd_key = HdKey {
            seed: hd_seed,
            staking_index: 0,
            transfer_index: 0,
            viewkey_index: 0,
        };
        let (view_key, priv_key) = hd_key
            .seed
            .derive_key_pair(network, HDAccountType::Viewkey.index(), 0)
            .expect("invalid seed");
        let mut wallet = TestVectorWallet {
            hd_key,
            view_key: (view_key, priv_key),
            transfer_addresses: vec![],
            staking_address: None,
        };
        let _ = wallet.create_transfer_address(network);
        wallet.create_staking_address(network);
        let chain_hex_id = match network {
            Network::Testnet => 0x42,
            Network::Mainnet => 0x2A,
            Network::Devnet => 0x0, // TODO: custom argument?
        };
        let test_vectors = TestVectors::default();
        Self {
            network,
            chain_hex_id,
            wallet,
            test_vectors,
        }
    }

    pub fn create_withdraw_unbonded_tx(&mut self) -> Result<TxId> {
        let amount = Coin::from(1000);
        let view_key = self.wallet.view_key.clone();
        let nonce = 0;
        let (from_addr, _, sign_key) = self.wallet.staking_address.clone().unwrap();
        let to_addr = self.wallet.transfer_addresses[0].0.clone();
        let output = TxOut::new_with_timelock(to_addr.clone(), amount, 0);
        let attributes = TxAttributes::new_with_access(
            self.chain_hex_id,
            vec![TxAccessPolicy::new(view_key.0.into(), TxAccess::AllData)],
        );
        let transaction = WithdrawUnbondedTx::new(nonce, vec![output], attributes);
        let tx = Transaction::WithdrawUnbondedStakeTransaction(transaction.clone());
        let txid = tx.id();
        let witness = sign_key.sign(&tx).map(StakedStateOpWitness::new)?;
        let plain_tx_aux = PlainTxAux::WithdrawUnbondedStakeTx(transaction);
        let withdraw_unbonded_vector = WithdrawUnboundedVector {
            to_address: to_addr.to_cro(self.network).unwrap(),
            from_address: format!("{}", from_addr),
            coin_amount: format!("{:?}", amount),
            witness: hex::encode(witness.encode()),
            plain_tx_aux: hex::encode(plain_tx_aux.encode()),
            tx_id: hex::encode(txid),
            view_keys: vec![hex::encode(self.wallet.view_key.0.serialize())],
        };
        self.test_vectors.withdraw_unbonded_vector = Some(withdraw_unbonded_vector);
        Ok(txid)
    }

    pub fn create_transfer_tx(&mut self, withdraw_unbonded_tx_id: TxId) -> Result<()> {
        let public_key = self.wallet.transfer_addresses[0].1.clone();
        let sign_key = self.wallet.transfer_addresses[0].2.clone();
        let (return_address, _, _) = self.wallet.create_transfer_address(self.network)?;
        let (to_address, _, _) = self.wallet.create_transfer_address(self.network)?;
        let inputs = vec![TxoPointer::new(withdraw_unbonded_tx_id, 0)];
        let transfer_amount = Coin::from(100);
        let return_amount = Coin::from(900);
        let outputs = vec![
            TxOut::new(return_address.clone(), return_amount),
            TxOut::new(to_address.clone(), transfer_amount),
        ];
        let view_keys = vec![self.wallet.view_key.clone()];
        let access_policies = view_keys
            .iter()
            .map(|key| TxAccessPolicy {
                view_key: key.0.clone().into(),
                access: TxAccess::AllData,
            })
            .collect();
        let attributes = TxAttributes::new_with_access(self.chain_hex_id, access_policies);
        let tx = Tx::new_with(inputs.clone(), outputs.clone(), attributes);
        let tx_id = tx.id();
        let proof = TestVectorWallet::gen_proof(public_key)?.unwrap();
        let witness: TxWitness = vec![TxInWitness::TreeSig(
            sign_key.schnorr_sign(&Transaction::TransferTransaction(tx.clone()))?,
            proof,
        )]
        .into();
        let plain_tx_aux = PlainTxAux::TransferTx(tx, witness.clone());
        let transfer_vector = TransferVector {
            to_address: to_address.to_cro(self.network).unwrap(),
            return_address: return_address.to_cro(self.network).unwrap(),
            transfer_amount: format!("{:?}", transfer_amount),
            return_amount: format!("{:?}", return_amount),
            inputs: inputs.iter().map(|i| hex::encode(i.encode())).collect(),
            outputs: outputs.iter().map(|o| hex::encode(o.encode())).collect(),
            witness: hex::encode(witness.encode()),
            plain_tx_aux: hex::encode(plain_tx_aux.encode()),
            tx_id: hex::encode(tx_id),
        };
        self.test_vectors.transfer_vector = Some(transfer_vector);
        Ok(())
    }

    fn create_deposit_stake_tx(&mut self, withdraw_unbonded_tx_id: TxId) -> Result<()> {
        let public_key = self.wallet.transfer_addresses[0].1.clone();
        let sign_key = self.wallet.transfer_addresses[0].2.clone();
        let utxo = TxoPointer::new(withdraw_unbonded_tx_id, 0);
        let staking_address = self.wallet.staking_address.clone().unwrap().0;
        let attributes = StakedStateOpAttributes::new(self.chain_hex_id);
        let tx = DepositBondTx::new(vec![utxo], staking_address, attributes);
        let proof = TestVectorWallet::gen_proof(public_key)?.unwrap();
        let witness: TxWitness = vec![TxInWitness::TreeSig(
            sign_key.schnorr_sign(&Transaction::DepositStakeTransaction(tx.clone()))?,
            proof,
        )]
        .into();
        let tx_id = tx.id();

        let deposit_vector = DepositStakeVector {
            staking_address: format!("{}", staking_address),
            witness: hex::encode(witness.encode()),
            transaction: hex::encode(tx.encode()),
            tx_id: hex::encode(tx_id),
        };
        self.test_vectors.deposit_stake_vector = Some(deposit_vector);
        Ok(())
    }

    fn create_nodejoin_tx(&mut self) -> Result<()> {
        let (staking_address, _, sign_key) = self.wallet.staking_address.clone().unwrap();
        let pk = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap();
        let mut pkl = [0u8; 32];
        pkl.copy_from_slice(&pk);
        let tendermint_validator_pubkey = TendermintValidatorPubKey::Ed25519(pkl);
        let tx = NodeJoinRequestTx::new(
            1,
            staking_address,
            StakedStateOpAttributes::new(self.chain_hex_id),
            CouncilNode::new_with_details(
                "example".to_string(),
                Some("security@example.com".to_string()),
                tendermint_validator_pubkey.clone(),
                ConfidentialInit {
                    keypackage: b"FIXME".to_vec(),
                },
            ),
        );
        let txid = tx.id();
        let witness = sign_key
            .sign(&Transaction::NodejoinTransaction(tx.clone()))
            .map(StakedStateOpWitness::new)?;
        let nodejoin_tx = TxAux::PublicTx(TxPublicAux::NodeJoinTx(tx, witness.clone()));
        let nodejoin_vector = NodeJoinVector {
            staking_address: format!("{}", staking_address),
            tendermint_validator_pubkey: hex::encode(tendermint_validator_pubkey.encode()),
            witness: hex::encode(witness.encode()),
            tx: hex::encode(nodejoin_tx.encode()),
            tx_id: hex::encode(&txid),
        };
        self.test_vectors.nodejoin_vector = Some(nodejoin_vector);
        Ok(())
    }

    fn create_unbonded_stake_tx(&mut self) -> Result<()> {
        let (staking_address, _, sign_key) = self.wallet.staking_address.clone().unwrap();
        let tx = UnbondTx::new(
            staking_address,
            0,
            Coin::from(1000),
            StakedStateOpAttributes::new(self.chain_hex_id),
        );
        let txid = tx.id();
        let transaction = Transaction::UnbondStakeTransaction(tx.clone());
        let witness = sign_key.sign(&transaction).map(StakedStateOpWitness::new)?;
        let unbond_tx = TxAux::PublicTx(TxPublicAux::UnbondStakeTx(tx, witness.clone()));
        let unbonded_stake_vector = UnboundedStakeVector {
            staking_address: format!("{}", staking_address),
            witness: hex::encode(witness.encode()),
            tx: hex::encode(unbond_tx.encode()),
            tx_id: hex::encode(&txid),
        };
        self.test_vectors.unbonded_stake_vector = Some(unbonded_stake_vector);
        Ok(())
    }

    pub fn create_test_vectors(&mut self) -> Result<()> {
        self.test_vectors.wallet_view_key = Some(hex::encode(self.wallet.view_key.0.serialize()));
        let tx_id = self.create_withdraw_unbonded_tx().unwrap();
        self.create_transfer_tx(tx_id.clone())?;
        self.create_deposit_stake_tx(tx_id.clone())?;
        self.create_nodejoin_tx()?;
        self.create_unbonded_stake_tx()?;
        println!(
            "view secret key: {}",
            hex::encode(self.wallet.view_key.1.serialize())
        );
        if let Some((ref address, ref public, ref secret)) = self.wallet.staking_address {
            println!("staking address: {:?}", address);
            println!("secret: {}", hex::encode(secret.serialize()));
            println!("public key: {}", hex::encode(public.serialize()));
        }

        for (address, public, secret) in self.wallet.transfer_addresses.iter() {
            println!("transfer address");
            println!("mainnet: {}", address.to_cro(Network::Mainnet).unwrap());
            println!(
                "public testnet: {}",
                address.to_cro(Network::Testnet).unwrap()
            );
            let xonly =
                XOnlyPublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from(secret));
            println!("secret: {}", hex::encode(secret.serialize()));
            println!("public key: {}", hex::encode(public.serialize()));
            println!("X only public key: {}", hex::encode(&xonly.serialize()));
        }

        println!(
            "{}",
            serde_json::to_string_pretty(&self.test_vectors).unwrap()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vectors() {
        let seed = hex::decode("9ee5468093cf78ce008ace0b676b606d94548f8eac79e727e3cb0500ae739facca7bb5ee1f3dd698bc6fcd044117905d42d90fadf324c6187e1faba7e662410f").unwrap();
        println!("seed: {:?}", hex::encode(seed.clone()));
        let mut work_flow = VectorFactory::new(Network::Devnet, seed);
        assert!(work_flow.create_test_vectors().is_ok());
    }
}
