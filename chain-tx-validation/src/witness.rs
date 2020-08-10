use chain_core::init::address::RedeemAddress;
use chain_core::state::account::{StakedStateAddress, StakedStateOpWitness};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::TxId;
use chain_core::tx::witness::TxInWitness;
use secp256k1::{key::XOnlyPublicKey, schnorrsig::schnorr_verify, Message};

/// verify a given extended address is associated to the witness
/// and the signature against the given transaction `Tx`
/// TODO: capture possible errors in enum?
///
pub fn verify_tx_address(
    witness: &TxInWitness,
    txid: &TxId,
    address: &ExtendedAddr,
) -> Result<(), secp256k1::Error> {
    let secp = secp256k1::SECP256K1;
    let message = Message::from_slice(&txid[..])?;

    match (witness, address) {
        (TxInWitness::TreeSig(sig, proof), ExtendedAddr::OrTree(root_hash)) => {
            if !proof.verify(root_hash) {
                Err(secp256k1::Error::InvalidPublicKey)
            } else {
                schnorr_verify(
                    &secp,
                    &message,
                    &sig,
                    &XOnlyPublicKey::from_slice(proof.value().as_bytes())?,
                )
            }
        }
    }
}

/// verify the signature against the given transation `Tx`
/// and recovers the address from it
///
pub fn verify_tx_recover_address(
    witness: &StakedStateOpWitness,
    txid: &TxId,
) -> Result<StakedStateAddress, secp256k1::Error> {
    match witness {
        StakedStateOpWitness::BasicRedeem(sig) => {
            let secp = secp256k1::SECP256K1;
            let message = Message::from_slice(txid)?;
            let pk = secp.recover(&message, &sig)?;
            secp.verify(&message, &sig.to_standard(), &pk)?;
            Ok(StakedStateAddress::BasicRedeem(RedeemAddress::from(&pk)))
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use secp256k1::schnorrsig::schnorr_sign;
    use secp256k1::{PublicKey, SecretKey};

    use chain_core::common::MerkleTree;
    use chain_core::tx::data::Tx;
    use chain_core::tx::witness::tree::RawXOnlyPubkey;
    use chain_core::tx::TransactionId;

    #[test]
    fn check_1_of_1_verify() {
        let transation = Tx::new();

        let secp = secp256k1::SECP256K1;

        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("Unable to create secret key");
        let public_key = XOnlyPublicKey::from_secret_key(&secp, &secret_key);

        let merkle_tree = MerkleTree::new(vec![RawXOnlyPubkey::from(public_key.serialize())]);
        let address = ExtendedAddr::OrTree(merkle_tree.root_hash());

        let witness = TxInWitness::TreeSig(
            schnorr_sign(
                &secp,
                &Message::from_slice(&transation.id()).unwrap(),
                &secret_key,
                &mut rand::thread_rng(),
            ),
            merkle_tree
                .generate_proof(RawXOnlyPubkey::from(public_key.serialize()))
                .unwrap(),
        );

        assert!(verify_tx_address(&witness, &transation.id(), &address).is_ok())
    }

    #[test]
    fn check_1_of_2_verify() {
        let transation = Tx::new();

        let secp = secp256k1::SECP256K1;

        let secret_keys = [
            SecretKey::from_slice(&[0xcd; 32]).expect("Unable to create secret key"),
            SecretKey::from_slice(&[0xde; 32]).expect("Unable to create secret key"),
        ];
        let public_keys = [
            XOnlyPublicKey::from_secret_key(&secp, &secret_keys[0]),
            XOnlyPublicKey::from_secret_key(&secp, &secret_keys[1]),
        ];

        let merkle_tree = MerkleTree::new(vec![
            RawXOnlyPubkey::from(public_keys[0].serialize()),
            RawXOnlyPubkey::from(public_keys[1].serialize()),
        ]);
        let address = ExtendedAddr::OrTree(merkle_tree.root_hash());

        let witness = TxInWitness::TreeSig(
            schnorr_sign(
                &secp,
                &Message::from_slice(&transation.id()).unwrap(),
                &secret_keys[0],
                &mut rand::thread_rng(),
            ),
            merkle_tree
                .generate_proof(RawXOnlyPubkey::from(public_keys[0].serialize()))
                .unwrap(),
        );

        assert!(verify_tx_address(&witness, &transation.id(), &address).is_ok())
    }

    #[test]
    fn check_1_of_2_incorrect_proof() {
        let transation = Tx::new();

        let secp = secp256k1::SECP256K1;

        let secret_keys = [
            SecretKey::from_slice(&[0xcd; 32]).expect("Unable to create secret key"),
            SecretKey::from_slice(&[0xde; 32]).expect("Unable to create secret key"),
        ];
        let public_keys = [
            XOnlyPublicKey::from_secret_key(&secp, &secret_keys[0]),
            XOnlyPublicKey::from_secret_key(&secp, &secret_keys[1]),
        ];

        let merkle_tree = MerkleTree::new(vec![
            RawXOnlyPubkey::from(public_keys[0].serialize()),
            RawXOnlyPubkey::from(public_keys[1].serialize()),
        ]);
        let address = ExtendedAddr::OrTree(merkle_tree.root_hash());

        let witness = TxInWitness::TreeSig(
            schnorr_sign(
                &secp,
                &Message::from_slice(&transation.id()).unwrap(),
                &secret_keys[0],
                &mut rand::thread_rng(),
            ),
            merkle_tree
                .generate_proof(RawXOnlyPubkey::from(public_keys[1].serialize()))
                .unwrap(),
        );

        assert!(verify_tx_address(&witness, &transation.id(), &address).is_err())
    }

    #[test]
    fn check_staked_verify() {
        let transation = Tx::new();

        let secp = secp256k1::SECP256K1;

        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("Unable to create secret key");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let address = StakedStateAddress::BasicRedeem(RedeemAddress::from(&public_key));

        let message = Message::from_slice(&transation.id()).unwrap();

        let signature = secp.sign_recoverable(&message, &secret_key);
        let witness = StakedStateOpWitness::BasicRedeem(signature);

        let recovered_address = verify_tx_recover_address(&witness, &transation.id())
            .expect("Unable to verify signature");

        assert_eq!(address, recovered_address);
    }
}
