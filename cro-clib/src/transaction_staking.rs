use crate::types::get_string;
use crate::types::{CroAddress, CroAddressPtr, CroResult};
pub use chain_core::init::network::Network;
use chain_core::state::account::{
    ConfidentialInit, MLSInit, NodeMetadata, StakedStateAddress, StakedStateOpAttributes,
    StakedStateOpWitness, UnjailTx,
};
use chain_core::state::tendermint::TendermintValidatorPubKey;
use chain_core::state::validator::NodeJoinRequestTx;
use chain_core::tx::{TxAux, TxPublicAux};
use client_common::temporary_mls_init;
use client_common::{ErrorKind, PrivateKeyAction, Result, ResultExt, Transaction};
use parity_scale_codec::Encode;
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use std::str::FromStr;
use std::string::ToString;

/// staked -> staked
/// network: networkid   ex) 0xab
/// nonce: nonce of the staked state, use cro_get_staked_state to get this nonce
/// from_ptr: staking address
/// to_address_user:staking address, null terminated string   ex) 0x1ad06eef15492a9a1ed0cfac21a1303198db8840
fn create_encoded_signed_unjail(
    network: u8,
    nonce: u64,
    from_address: &CroAddress,
    to_address_user: &str,
) -> Result<Vec<u8>> {
    let to_address = StakedStateAddress::from_str(&to_address_user).chain(|| {
        (
            ErrorKind::DeserializationError,
            format!("Unable to deserialize to_address ({})", to_address_user),
        )
    })?;
    let attributes = StakedStateOpAttributes::new(network);
    let transaction: UnjailTx = UnjailTx::new(nonce, to_address, attributes);
    let tx = Transaction::UnjailTransaction(transaction.clone());
    let from_private = &from_address.privatekey;
    let signature: StakedStateOpWitness = from_private.sign(&tx).map(StakedStateOpWitness::new)?;
    let result = TxAux::PublicTx(TxPublicAux::UnjailTx(transaction, signature));
    let encoded = result.encode();
    Ok(encoded)
}

/// staked -> staked
/// network: networkid   ex) 0xab
/// nonce: nonce of the staked state, use cro_get_staked_state to get this nonce
/// from_ptr: staking address
/// to_address_user:staking address, null terminated string   ex) 0x1ad06eef15492a9a1ed0cfac21a1303198db8840
/// output: signed tx encoded, minimum 1000 bytes
/// output_length: actual encoded length is returned
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_unjai(
    network: u8,
    nonce: u64,
    from_ptr: CroAddressPtr,
    to_address_user: *const c_char,
    output: *mut u8,
    output_length: *mut u32,
) -> CroResult {
    let to_address = get_string(to_address_user);
    let from_address = from_ptr.as_mut().expect("get address");

    match create_encoded_signed_unjail(network, nonce, from_address, &to_address) {
        Ok(encoded) => {
            ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len());
            (*output_length) = encoded.len() as u32;

            CroResult::success()
        }
        Err(_) => CroResult::fail(),
    }
}

/// staked -> staked
/// network: networkid   ex) 0xab
/// nonce: nonce of the staked state, use cro_get_staked_state to get this nonce
/// from_ptr: staking address
/// to_address_user:staking address, null terminated string
/// validator_name_user: validator name, null terminated string
/// validator_contact_user: validator contact, null terminated string
/// validator_pubkey_user: validator pubkey,ed25519 pubkey raw size= 32 bytes , base64 encoded  null terminated string,  
/// FIXME: Add+Commit instead of keypackage
#[allow(clippy::too_many_arguments)]
fn create_encoded_signed_join(
    network: u8,
    nonce: u64,
    from_address: &CroAddress,
    to_address_user: &str,
    validator_name: &str,
    validator_contact: &str,
    validator_pubkey: &str,
    keypackage: Vec<u8>,
) -> Result<Vec<u8>> {
    let to_address = StakedStateAddress::from_str(&to_address_user).chain(|| {
        (
            ErrorKind::DeserializationError,
            format!("Unable to deserialize to_address ({})", to_address_user),
        )
    })?;
    let attributes = StakedStateOpAttributes::new(network);
    let pubkey: TendermintValidatorPubKey =
        TendermintValidatorPubKey::from_base64(validator_pubkey.as_bytes()).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to get validator pubkey",
            )
        })?;
    // FIXME: MLSPlaintexts instead of keypackage
    let node_metadata = NodeMetadata::new_council_node_with_details(
        validator_name.to_string(),
        Some(validator_contact.to_string()),
        // 32 bytes
        pubkey,
        ConfidentialInit {
            init_payload: MLSInit::NodeJoin {
                add: temporary_mls_init(keypackage),
                commit: vec![],
            },
        },
    );
    let transaction: NodeJoinRequestTx = NodeJoinRequestTx {
        nonce,
        address: to_address,
        attributes,
        node_meta: node_metadata,
    };
    let tx = Transaction::NodejoinTransaction(transaction.clone());
    let from_private = &from_address.privatekey;
    let signature: StakedStateOpWitness = from_private.sign(&tx).map(StakedStateOpWitness::new)?;
    let result = TxAux::PublicTx(TxPublicAux::NodeJoinTx(transaction, signature));
    let encoded = result.encode();
    Ok(encoded)
}

/// staked -> staked
/// network: networkid    ex) 0xab
/// nonce: nonce of the staked state, use cro_get_staked_state to get this nonce
/// from_ptr: staking address
/// to_address_user:staking address, null terminated string
/// validator_name_user: validator name, null terminated string
/// validator_contact_user: validator contact, null terminated string
/// validator_pubkey_user: validator pubkey,ed25519 pubkey raw size= 32 bytes , base64 encoded  null terminated string,  
/// output: signed tx encoded, minimum 1000 bytes
/// output_length: actual encoded length is returned
#[no_mangle]
/// # Safety
pub unsafe extern "C" fn cro_join(
    network: u8,
    nonce: u64,
    from_ptr: CroAddressPtr,
    to_address_user: *const c_char,
    validator_name_user: *const c_char,
    validator_contact_user: *const c_char,
    validator_pubkey_user: *const c_char,
    keypackage: *const u8,
    keypackage_len: usize,
    output: *mut u8,
    output_length: *mut u32,
) -> CroResult {
    let to_address = get_string(to_address_user);
    let validator_name = get_string(validator_name_user);
    let validator_contact = get_string(validator_contact_user);
    let validator_pubkey = get_string(validator_pubkey_user);
    let from_address = from_ptr.as_mut().expect("get address");

    match create_encoded_signed_join(
        network,
        nonce,
        from_address,
        &to_address,
        &validator_name,
        &validator_contact,
        &validator_pubkey,
        slice::from_raw_parts(keypackage, keypackage_len).to_vec(),
    ) {
        Ok(encoded) => {
            ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len());
            (*output_length) = encoded.len() as u32;

            CroResult::success()
        }
        Err(_) => CroResult::fail(),
    }
}
