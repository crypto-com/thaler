use parity_scale_codec::Encode;
use serde::Serialize;

use chain_core::common::Proof;
use chain_core::init::address::{CroAddress, RedeemAddress};
use chain_core::init::coin::Coin;
use chain_core::init::network::Network;
use chain_core::state::account::{
    CouncilNodeMeta, DepositBondTx, NodeMetadata, StakedStateAddress, StakedStateOpAttributes,
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
use test_common::chain_env::mock_confidential_init;

#[derive(Debug)]
pub struct TestVectorCommand {
    network: Network,
    seed: Vec<u8>,
    aux_payload: Vec<u8>,
}

impl TestVectorCommand {
    pub fn new(network: String, seed: String, aux_payload: &str) -> Self {
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
        let aux_payload = hex::decode(&aux_payload).expect("invalid hex encoded aux payload");
        Self {
            network,
            seed,
            aux_payload,
        }
    }

    pub fn execute(&self) -> Result<()> {
        let mut vector_factory = VectorFactory::new(self.network, self.seed.clone());
        vector_factory.create_test_vectors(&self.aux_payload)
    }
}

#[derive(Debug, Clone, Serialize)]
struct WithdrawUnboundedVector {
    pub from_address: String,
    pub to_address: String,
    pub coin_amount: String,
    pub witness: String,
    pub plain_tx_aux: String,
    pub tx_id: String,
    pub view_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct TransferVector {
    pub to_address: String,
    pub return_address: String,
    pub transfer_amount: String,
    pub return_amount: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub witness: String,
    pub plain_tx_aux: String,
    pub tx_id: String,
}

#[derive(Debug, Clone, Serialize)]
struct DepositStakeVector {
    pub staking_address: String,
    pub witness: String,
    pub transaction: String,
    pub tx_id: String,
}

#[derive(Debug, Clone, Serialize)]
struct NodeJoinVector {
    pub staking_address: String,
    pub tendermint_validator_pubkey: String,
    pub witness: String,
    pub tx: String,
    pub tx_id: String,
}

#[derive(Debug, Clone, Serialize)]
struct UnboundedStakeVector {
    pub staking_address: String,
    pub witness: String,
    pub tx: String,
    pub tx_id: String,
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
    pub hd_key: HdKey,
    pub view_key: (PublicKey, PrivateKey),
    pub transfer_addresses: Vec<(ExtendedAddr, PublicKey, PrivateKey)>,
    pub staking_address: Option<(StakedStateAddress, PublicKey, PrivateKey)>,
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

    pub fn create_transfer_tx(
        &mut self,
        withdraw_unbonded_tx_id: TxId,
        aux_payload: &[u8],
    ) -> Result<()> {
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
            sign_key
                .schnorr_sign_unsafe(&Transaction::TransferTransaction(tx.clone()), &aux_payload)?,
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

    fn create_deposit_stake_tx(
        &mut self,
        withdraw_unbonded_tx_id: TxId,
        aux_payload: &[u8],
    ) -> Result<()> {
        let public_key = self.wallet.transfer_addresses[0].1.clone();
        let sign_key = self.wallet.transfer_addresses[0].2.clone();
        let utxo = TxoPointer::new(withdraw_unbonded_tx_id, 0);
        let staking_address = self.wallet.staking_address.clone().unwrap().0;
        let attributes = StakedStateOpAttributes::new(self.chain_hex_id);
        let tx = DepositBondTx::new(vec![utxo], staking_address, attributes);
        let proof = TestVectorWallet::gen_proof(public_key)?.unwrap();
        let witness: TxWitness = vec![TxInWitness::TreeSig(
            sign_key.schnorr_sign_unsafe(
                &Transaction::DepositStakeTransaction(tx.clone()),
                aux_payload,
            )?,
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
            NodeMetadata::CouncilNode(CouncilNodeMeta::new_with_details(
                "example".to_string(),
                Some("security@example.com".to_string()),
                tendermint_validator_pubkey.clone(),
                mock_confidential_init(),
            )),
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

    pub fn create_test_vectors(&mut self, aux_payload: &[u8]) -> Result<()> {
        self.test_vectors.wallet_view_key = Some(hex::encode(self.wallet.view_key.0.serialize()));
        let tx_id = self.create_withdraw_unbonded_tx().unwrap();
        self.create_transfer_tx(tx_id, aux_payload)?;
        self.create_deposit_stake_tx(tx_id, aux_payload)?;
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
        let mut work_flow = VectorFactory::new(Network::Devnet, seed);
        let aux_payload: [u8; 32] = [0; 32];
        assert!(work_flow.create_test_vectors(&aux_payload).is_ok());
        let transafer_addresses = &work_flow.wallet.transfer_addresses;
        let statking_address = work_flow.wallet.staking_address.clone().unwrap();
        // check addresses
        assert_eq!(
            work_flow.wallet.view_key.0.to_string(),
            "036b3e5b7744134ac0556ace88b098a057014afb82701b1b1ba49ea04b09fea29b"
        );
        assert_eq!(work_flow.wallet.transfer_addresses.len(), 3);
        assert_eq!(
            transafer_addresses[0].0.to_string(),
            "dcro1p89u9nsd6v2dtf7xtryxdf867tv9zrrfzgcnsk0wayyry27hmt6ssl5msc"
        );
        assert_eq!(
            transafer_addresses[0].1.to_string(),
            "039f561c58a9f431952ee67dbead4896f2dc41735319d9b2b89211358b0c283356"
        );
        assert_eq!(
            hex::encode(transafer_addresses[0].2.serialize()),
            "496512d4512400226ae72eabd2723496108535ae0743d4e7fcecdf581005adac"
        );
        assert_eq!(
            transafer_addresses[1].0.to_string(),
            "dcro17kf3nmtpm7erknjjv3zer70e07208y672q0dl3tfwaxtlqyytrksdkyfwy"
        );
        assert_eq!(
            transafer_addresses[1].1.to_string(),
            "02a57069e830201cadd1f1fae4bd029f2558a40df9f887cc6978f03c968114156a"
        );
        assert_eq!(
            hex::encode(transafer_addresses[1].2.serialize()),
            "8f3b2dba80cbdeb3824cc0237db7a3743067a088f513fa3a64c4d12c63cf4bdf"
        );
        assert_eq!(
            transafer_addresses[2].0.to_string(),
            "dcro12nlpnzdjp4tg073wad0hs6d544nqdsl5gmcqd7lclmuzh8rl23mq34x46d"
        );
        assert_eq!(
            transafer_addresses[2].1.to_string(),
            "0220005730e244e65f3d6bf86c3cbeb122c3670b4551fb67b056d7fe8d5981a9f6"
        );
        assert_eq!(
            hex::encode(transafer_addresses[2].2.serialize()),
            "ec39eb306bac78b7008756bb28aa2fa88d1664fbcb551b34d6d71d2e7322ab57"
        );
        assert_eq!(
            statking_address.0.to_string(),
            "0xbce02627ca9daa2af92412cb9998aa59df127079"
        );
        assert_eq!(
            statking_address.1.to_string(),
            "032c8d58a2666af8355865ec819cd8ddc10d4260c9df1970e21c6af2c3ed4ab66e"
        );
        assert_eq!(
            hex::encode(statking_address.2.serialize()),
            "a9ad4bb94865a7a79b9dd574696d03615eeb69c117490e2cc904338df832b0e5"
        );

        // check test vectors
        let test_vectors = &work_flow.test_vectors;
        assert_eq!(test_vectors.wallet_view_key.clone().unwrap(), "046b3e5b7744134ac0556ace88b098a057014afb82701b1b1ba49ea04b09fea29b9430a4059e9abceb251eb6a3ec8968e01e2bc0f3fc352b56ed78313c96110403");
        // check withdraw unbounded
        let withdraw_unbounded_vector = test_vectors.withdraw_unbonded_vector.clone().unwrap();
        assert_eq!(
            withdraw_unbounded_vector.from_address,
            "0xbce02627ca9daa2af92412cb9998aa59df127079"
        );
        assert_eq!(
            withdraw_unbounded_vector.to_address,
            "dcro1p89u9nsd6v2dtf7xtryxdf867tv9zrrfzgcnsk0wayyry27hmt6ssl5msc"
        );
        assert_eq!(
            withdraw_unbounded_vector.coin_amount,
            format!("{:?}", Coin::new(1000).unwrap())
        );
        assert_eq!(withdraw_unbounded_vector.witness, "000191be892928806cbc1016e4f756facf143e40f2e681b000989521353a2e2a01d842f57ed373e09621f40e86f3555ddd00ef1a7221498bd112f5732db6109473b1");
        assert_eq!(withdraw_unbounded_vector.plain_tx_aux, "020000000000000000040009cbc2ce0dd314d5a7c658c866a4faf2d8510c6912313859eee908322bd7daf5e803000000000000010000000000000000000004036b3e5b7744134ac0556ace88b098a057014afb82701b1b1ba49ea04b09fea29b000100000000000000");
        assert_eq!(
            withdraw_unbounded_vector.tx_id,
            "e83d1e15bc3d4d80e7c61d00623af277cc792f503794e096fe8e4434371318b3"
        );
        // check transfer vector
        let transfer_vector = test_vectors.transfer_vector.clone().unwrap();
        assert_eq!(
            transfer_vector.to_address,
            "dcro12nlpnzdjp4tg073wad0hs6d544nqdsl5gmcqd7lclmuzh8rl23mq34x46d"
        );
        assert_eq!(
            transfer_vector.return_address,
            "dcro17kf3nmtpm7erknjjv3zer70e07208y672q0dl3tfwaxtlqyytrksdkyfwy"
        );
        assert_eq!(
            transfer_vector.transfer_amount,
            format!("{:?}", Coin::new(100).unwrap())
        );
        assert_eq!(
            transfer_vector.return_amount,
            format!("{:?}", Coin::new(900).unwrap())
        );
        assert_eq!(transfer_vector.witness, "0400d81d11786ed494ef7bb421cf3d05c033aa9e263f58a4a18c400a50e5b9560b8078fc4b7fe9ea73bb7ab14f05cfe1a03b2e3610a2363e651405ca6795704599f1009f561c58a9f431952ee67dbead4896f2dc41735319d9b2b89211358b0c283356");
        assert_eq!(
            transfer_vector.inputs,
            vec!["e83d1e15bc3d4d80e7c61d00623af277cc792f503794e096fe8e4434371318b30000"]
        );
        assert_eq!(
            transfer_vector.outputs,
            vec![
            "00f59319ed61dfb23b4e52644591f9f97f94f3935e501edfc569774cbf808458ed840300000000000000",
            "0054fe1989b20d5687fa2eeb5f7869b4ad6606c3f446f006fbf8fef82b9c7f5476640000000000000000"
        ]
        );
        // check deposit stake vector
        let deposit_vector = test_vectors.deposit_stake_vector.clone().unwrap();
        assert_eq!(
            deposit_vector.staking_address,
            "0xbce02627ca9daa2af92412cb9998aa59df127079"
        );
        assert_eq!(deposit_vector.witness, "0400e0cc58de1add5f0262e212b67d98b2c2f0c23ff94a923f427a9d7c8f464a90b81b837f45b3e9c2d2fdab3de2998b8f85be388b855bbb3df8e9d81e2ec58b2005009f561c58a9f431952ee67dbead4896f2dc41735319d9b2b89211358b0c283356");
        assert_eq!(deposit_vector.transaction, "04e83d1e15bc3d4d80e7c61d00623af277cc792f503794e096fe8e4434371318b3000000bce02627ca9daa2af92412cb9998aa59df12707900000100000000000000");
        assert_eq!(
            deposit_vector.tx_id,
            "e9506043ab05b03ee0d6ecf6eb85ebd11fa3d6f04c017b9d94f6db66da488a13"
        );
        // check node join vector
        let nodejoin_vector = test_vectors.nodejoin_vector.clone().unwrap();
        assert_eq!(
            nodejoin_vector.staking_address,
            "0xbce02627ca9daa2af92412cb9998aa59df127079"
        );
        assert_eq!(
            nodejoin_vector.tendermint_validator_pubkey,
            "00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        // FIXME: update documentation, as in 0.6 the confidential init is defined
        assert_eq!(
            nodejoin_vector.tx_id,
            "5b096d800553c0e7d818bf2fa7027ddd14d59dfd554791d977371cd1337dce70"
        );
        // check unbonded stake vector
        let unbonded_stake_vector = test_vectors.unbonded_stake_vector.clone().unwrap();
        assert_eq!(
            unbonded_stake_vector.staking_address,
            "0xbce02627ca9daa2af92412cb9998aa59df127079"
        );
        assert_eq!(unbonded_stake_vector.witness, "0001686d772b75f229beb68b761432148eaa762d6bc38d89cc76b90799e1cea7d0ab34b5dd4740a0a1dc06f4d7f25f9747b8b6c14e50a6176cc6e55e9f3005556cc2");
        assert_eq!(
            unbonded_stake_vector.tx_id,
            "7600e018d9f225fac168ef73708150b590f12105b1408f16eb2aaa88a42b50d7"
        );
    }
}
