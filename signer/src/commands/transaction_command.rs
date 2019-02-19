use failure::{format_err, Error, ResultExt};
use hex::{decode, encode};
use quest::{ask, choose, text, yesno, success};
use secp256k1zkp::aggsig::{add_signatures_single, export_secnonce_single, sign_single};
use secp256k1zkp::key::PublicKey;
use secp256k1zkp::{Message, Secp256k1};
use serde_cbor::ser::to_vec_packed;
use sled::Db;
use structopt::StructOpt;

use chain_core::common::{Timespec, HASH_SIZE_256};
use chain_core::init::address::REDEEM_ADDRESS_BYTES;
use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::witness::redeem::EcdsaSignature;
use chain_core::tx::witness::tree::{pk_to_raw, sig_to_raw};
use chain_core::tx::witness::{TxInWitness, TxWitness};
use chain_core::tx::TxAux;

use crate::commands::{AddressCommand, Secrets};

/// Enum used to specify different subcommands under transaction command.
/// Refer to main documentation for more details.
#[derive(Debug, StructOpt)]
pub enum TransactionCommand {
    /// Used to generate a new transaction
    #[structopt(name = "generate", about = "Generate new transaction")]
    Generate {
        #[structopt(
            name = "chain-id",
            short,
            long,
            help = "Chain ID for transaction (Last two hex digits of chain-id)"
        )]
        chain_id: String,
        #[structopt(name = "name", short, long, help = "Name of signer")]
        name: String,
    },
}

/// Enum specifying different signature types
#[derive(Debug)]
enum SignatureType {
    ECDSA,
    Schnorr,
}

impl TransactionCommand {
    /// Executes current transaction command
    pub fn execute(&self, address_storage: &Db) -> Result<(), Error> {
        use TransactionCommand::*;

        match self {
            Generate { chain_id, name } => Self::generate(chain_id, name, address_storage),
        }
    }

    /// Verifies the transaction id
    fn verify_transaction_id(transaction_id: String) -> Result<TxId, Error> {
        let transaction_id = decode(&transaction_id)?;

        if HASH_SIZE_256 != transaction_id.len() {
            Err(format_err!("Invalid transaction id"))
        } else {
            let mut new_transaction_id: TxId = [0; HASH_SIZE_256];
            new_transaction_id.copy_from_slice(&transaction_id);
            Ok(new_transaction_id)
        }
    }

    /// Verifies redeem address
    fn verify_redeem_address(address: String) -> Result<ExtendedAddr, Error> {
        let address = decode(&address)?;

        if REDEEM_ADDRESS_BYTES != address.len() {
            Err(format_err!("Invalid redeem address"))
        } else {
            let mut addr = [0; REDEEM_ADDRESS_BYTES];
            addr.copy_from_slice(&address);
            Ok(ExtendedAddr::BasicRedeem(addr))
        }
    }

    /// Verifies tree address
    fn verify_tree_address(address: String) -> Result<ExtendedAddr, Error> {
        let address = decode(&address)?;

        if HASH_SIZE_256 != address.len() {
            Err(format_err!("Invalid tree address"))
        } else {
            let mut addr = [0; HASH_SIZE_256];
            addr.copy_from_slice(&address);
            Ok(ExtendedAddr::OrTree(addr))
        }
    }
    
    /// Returns ECDSA signature of message signed with provided secret
    fn get_ecdsa_signature(secrets: &Secrets, message: &Message) -> Result<TxInWitness, Error> {
        let secp = Secp256k1::new();

        let signature = secp.sign_recoverable(message, &secrets.spend)?;
        let (recovery_id, serialized_signature) = signature.serialize_compact(&secp);

        let r = &serialized_signature[0..32];
        let s = &serialized_signature[32..64];
        let mut sign = EcdsaSignature::default();

        sign.v = recovery_id.to_i32() as u8;
        sign.r.copy_from_slice(r);
        sign.s.copy_from_slice(s);

        Ok(TxInWitness::BasicRedeem(sign))
    }
    
    /// Returns Schonrr signature of message signed with provided secret
    fn get_schnorr_signature(secrets: &Secrets, message: &Message) -> Result<TxInWitness, Error> {
        let spend_public_key = AddressCommand::get_public_key(&secrets.spend)?;
        let view_public_key = AddressCommand::get_public_key(&secrets.view)?;

        let secp = Secp256k1::new();

        let secnonce_1 = export_secnonce_single(&secp)?;
        let secnonce_2 = export_secnonce_single(&secp)?;
        let pubnonce_2 = PublicKey::from_secret_key(&secp, &secnonce_2)?;
        let mut nonce_sum = pubnonce_2;
        nonce_sum.add_exp_assign(&secp, &secnonce_1)?;
        let mut pk_sum = view_public_key;
        pk_sum.add_exp_assign(&secp, &secrets.spend)?;
        let sig1 = sign_single(
            &secp,
            &message,
            &secrets.spend,
            Some(&secnonce_1),
            None,
            Some(&nonce_sum),
            Some(&pk_sum),
            Some(&nonce_sum),
        )?;
        let sig2 = sign_single(
            &secp,
            &message,
            &secrets.view,
            Some(&secnonce_2),
            None,
            Some(&nonce_sum),
            Some(&pk_sum),
            Some(&nonce_sum),
        )?;
        let sig = add_signatures_single(&secp, vec![&sig1, &sig2], &nonce_sum)?;
        let pk = PublicKey::from_combination(&secp, vec![&spend_public_key, &view_public_key])?;

        Ok(TxInWitness::TreeSig(
            pk_to_raw(&secp, pk),
            sig_to_raw(&secp, sig),
            vec![],
        ))
    }

    /// Returns transaction witnesses after signing
    fn get_transaction_witnesses(
        transaction: &Tx,
        secrets: &Secrets,
        required_signature_types: &[SignatureType],
    ) -> Result<TxWitness, Error> {
        let message = Message::from_slice(&transaction.id())?;

        let ecdsa_signature = Self::get_ecdsa_signature(secrets, &message)?;
        let schnorr_signature = Self::get_schnorr_signature(secrets, &message)?;

        let witnesses: Vec<TxInWitness> = required_signature_types
            .iter()
            .map(|x| match x {
                SignatureType::ECDSA => ecdsa_signature.clone(),
                SignatureType::Schnorr => schnorr_signature.clone(),
            })
            .collect();

        Ok(witnesses.into())
    }

    /// Takes transaction inputs from user
    fn ask_transaction_inputs(transaction: &mut Tx) -> Result<Vec<SignatureType>, Error> {
        let mut flag = true;

        let signature_types = &["ECDSA", "Schnorr"];
        let mut required_signature_types = Vec::new();

        while flag {
            ask("Enter input transaction ID: ");
            let transaction_id = Self::verify_transaction_id(text()?)?;

            ask("Enter index: ");
            let index = text()?
                .parse::<usize>()
                .context("Unable to parse to usize")?;

            ask("Signature type: \n");
            let signature_type = choose(Default::default(), signature_types)?;

            use SignatureType::*;

            required_signature_types.push(match signature_types[signature_type] {
                "ECDSA" => ECDSA,
                "Schnorr" => Schnorr,
                _ => unreachable!(),
            });

            transaction.add_input(TxoPointer::new(transaction_id, index));

            ask("More inputs? [yN] ");
            match yesno(false)? {
                None => Err(format_err!("Invalid response!"))?,
                Some(value) => flag = value,
            }
        }

        Ok(required_signature_types)
    }

    /// Takes transaction outputs from user
    fn ask_transaction_outputs(transaction: &mut Tx) -> Result<(), Error> {
        let mut flag = true;

        let address_types = &["Redeem", "Tree"];

        while flag {
            ask("Enter output address: ");
            let address = text()?;

            ask("Address type: \n");
            let address = match address_types[choose(Default::default(), address_types)?] {
                "Redeem" => Self::verify_redeem_address(address)?,
                "Tree" => Self::verify_tree_address(address)?,
                _ => unreachable!(),
            };

            ask("Enter amount: ");
            let amount = text()?.parse::<Coin>()?;

            ask("Enter timelock (seconds from UNIX epoch) (leave blank if output is not time locked): ");
            let timelock = text()?;

            if timelock.is_empty() {
                transaction.add_output(TxOut::new(address, amount));
            } else {
                transaction.add_output(TxOut::new_with_timelock(
                    address,
                    amount,
                    timelock.parse::<Timespec>()?,
                ));
            }

            ask("More outputs? [yN] ");
            match yesno(false)? {
                None => Err(format_err!("Invalid response!"))?,
                Some(value) => flag = value,
            }
        }

        Ok(())
    }

    /// Generates new transaction
    fn generate(chain_id: &str, name: &str, address_storage: &Db) -> Result<(), Error> {
        let secrets = AddressCommand::get_secrets(name, address_storage)?;

        let mut transaction = Tx::new();
        transaction.attributes = TxAttributes::new(decode(chain_id)?[0]);

        let required_signature_types = Self::ask_transaction_inputs(&mut transaction)?;

        Self::ask_transaction_outputs(&mut transaction)?;

        let witnesses =
            Self::get_transaction_witnesses(&transaction, &secrets, &required_signature_types)?;

        let txa = TxAux::new(transaction, witnesses);

        ask("Transaction ID: ");
        success(&format!("{}", encode(&txa.tx.id())));

        ask("Transaction: ");
        success(&format!("{}", encode(&to_vec_packed(&txa)?)));

        Ok(())
    }
}
