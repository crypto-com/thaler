use abci_enclave_macro::get_network_id;
use abci_enclave_protocol::{read_bincode, send_bincode, Error, SubAbciRequest, SubAbciResponse};
use chain_core::common::Timespec;
use chain_core::init::address::{keccak256, to_arr, RedeemAddressRaw};
use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::{txid_hash, Tx};
use chain_core::tx::witness::{tree::MerklePath, TxInWitness};
use chain_core::tx::TxAux;
use libsecp256k1::{
    curve::Scalar,
    recover,
    schnorr::{schnorr_verify, SchnorrSignature},
    util::COMPRESSED_PUBLIC_KEY_SIZE,
    verify, Message, PublicKey, PublicKeyFormat, RecoveryId, Signature,
};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::net::TcpStream;

const NETWORK_ID: u8 = get_network_id!();

#[inline]
fn get_recovery_id(rid: u8) -> Result<RecoveryId, Error> {
    match RecoveryId::parse(rid) {
        Ok(r) => Ok(r),
        Err(_) => Err(Error::WitnessVerificationFailed),
    }
}

#[inline]
fn recover_pk(message: &Message, sign: &Signature, ri: &RecoveryId) -> Result<PublicKey, Error> {
    match recover(message, sign, ri) {
        Ok(r) => Ok(r),
        Err(_) => Err(Error::WitnessVerificationFailed),
    }
}

#[inline]
fn parse_pk(pk_vec: &[u8]) -> Result<PublicKey, Error> {
    match PublicKey::parse_slice(pk_vec, Some(PublicKeyFormat::Compressed)) {
        Ok(r) => Ok(r),
        Err(_) => Err(Error::WitnessVerificationFailed),
    }
}

#[inline]
fn to_address(pk: &PublicKey) -> RedeemAddressRaw {
    let hash = keccak256(&pk.serialize()[1..]);
    to_arr(&hash[12..])
}

/// verify a given extended address is associated to the witness
/// and the signature against the given transation `Tx`
/// TODO: capture possible errors in enum?
///
pub fn verify_tx_address(
    witness: &TxInWitness,
    tx: &Tx,
    address: &ExtendedAddr,
) -> Result<(), Error> {
    let message = Message::parse(&tx.id());
    match (witness, address) {
        (TxInWitness::BasicRedeem(sig), ExtendedAddr::BasicRedeem(addr)) => {
            let mut r = Scalar::default();
            let _ = r.set_b32(&sig.r);
            let mut s = Scalar::default();
            let _ = s.set_b32(&sig.s);
            let sign = Signature { r, s };
            let ri = get_recovery_id(sig.v)?;
            let pk = recover_pk(&message, &sign, &ri)?;
            let expected_addr = to_address(&pk);
            // TODO: constant time eq?
            if *addr != expected_addr && !verify(&message, &sign, &pk) {
                Err(Error::WitnessVerificationFailed)
            } else {
                Ok(())
            }
        }
        (TxInWitness::TreeSig(pk, sig, ops), ExtendedAddr::OrTree(roothash)) => {
            let mut pk_vec = Vec::with_capacity(COMPRESSED_PUBLIC_KEY_SIZE);
            pk_vec.push(pk.0);
            pk_vec.extend(&pk.1);
            let mut pk_hash = txid_hash(&pk_vec);
            // TODO: blake2 tree hashing?
            for op in ops.iter() {
                let mut bs = vec![1u8];
                match op {
                    (MerklePath::LFound, data) => {
                        bs.extend(&pk_hash[..]);
                        bs.extend(&data[..]);
                        pk_hash = txid_hash(&bs);
                    }
                    (MerklePath::RFound, data) => {
                        bs.extend(&data[..]);
                        bs.extend(&pk_hash[..]);
                        pk_hash = txid_hash(&bs);
                    }
                }
            }
            let dpk = parse_pk(&pk_vec)?;
            let mut r = Scalar::default();
            let _ = r.set_b32(&sig.0);
            let mut s = Scalar::default();
            let _ = s.set_b32(&sig.1);
            let dsig = SchnorrSignature { r, s };
            // TODO: constant time eq?
            // TODO: migrate to upstream secp256k1 when Schnorr is available
            if pk_hash != *roothash && !schnorr_verify(&message, &dsig, &dpk) {
                Err(Error::WitnessVerificationFailed)
            } else {
                Ok(())
            }
        }
        (_, _) => Err(Error::WitnessVerificationFailed),
    }
}

fn verify_in_place(txaux: &TxAux, chain_hex_id: u8) -> Result<Coin, Error> {
    // TODO: check other attributes?
    // check that chain IDs match
    if chain_hex_id != txaux.tx.attributes.chain_hex_id {
        return Err(Error::WrongChainHexId);
    }
    // check that there are inputs
    if txaux.tx.inputs.is_empty() {
        return Err(Error::NoInputs);
    }

    // check that there are outputs
    if txaux.tx.outputs.is_empty() {
        return Err(Error::NoOutputs);
    }

    // check that there are no duplicate inputs
    let mut inputs = BTreeSet::new();
    if !txaux.tx.inputs.iter().all(|x| inputs.insert(x)) {
        return Err(Error::DuplicateInputs);
    }

    // check that all outputs have a non-zero amount
    if !txaux.tx.outputs.iter().all(|x| x.value > Coin::zero()) {
        return Err(Error::ZeroCoin);
    }

    // Note: we don't need to check against MAX_COIN because Coin's
    // constructor should already do it.

    // TODO: check address attributes?

    // verify transaction witnesses
    if txaux.tx.inputs.len() < txaux.witness.len() {
        return Err(Error::UnexpectedWitnesses);
    }

    if txaux.tx.inputs.len() > txaux.witness.len() {
        return Err(Error::MissingWitnesses);
    }
    let outsum = txaux.tx.get_output_total();
    if outsum.is_err() {
        return Err(Error::InvalidSum(outsum.unwrap_err()));
    }
    Ok(outsum.unwrap())
}

/// Checks TX against the current DB and returns an `Error` if something fails.
/// TODO: check Redeem addresses are never in outputs?
pub fn verify_with_storage(
    txaux: &TxAux,
    inputs: Vec<Tx>,
    block_time: Timespec,
) -> Result<(), Error> {
    let outcoins = verify_in_place(txaux, NETWORK_ID)?;
    let mut incoins = Coin::zero();

    // verify that txids of inputs correspond to the owner/signer
    // and it'd check they are not spent
    for (tx, (txin, in_witness)) in inputs
        .iter()
        .zip(txaux.tx.inputs.iter().zip(txaux.witness.iter()))
    {
        if tx.id() != txin.id || txin.index >= tx.outputs.len() {
            return Err(Error::InvalidInput);
        }
        let txout = &tx.outputs[txin.index];
        match txout.valid_from {
            Some(valid_from) if valid_from > block_time => {
                return Err(Error::OutputInTimelock);
            }
            _ => {}
        }

        let _ = verify_tx_address(&in_witness, &txaux.tx, &txout.address)?;

        let sum = incoins + txout.value;
        if sum.is_err() {
            return Err(Error::InvalidSum(sum.unwrap_err()));
        } else {
            incoins = sum.unwrap();
        }
    }
    // check sum(input amounts) == sum(output amounts)
    // TODO: do we allow "burn"? i.e. sum(input amounts) >= sum(output amounts)
    if incoins != outcoins {
        return Err(Error::InputOutputDoNotMatch);
    }
    Ok(())
}

fn respond(request: SubAbciRequest, stream: &mut Write) -> io::Result<()> {
    let resp = match request {
        SubAbciRequest::InitChain(chain_hex_id) if chain_hex_id == NETWORK_ID => {
            SubAbciResponse::InitChain(true)
        }
        SubAbciRequest::InitChain(_) => SubAbciResponse::InitChain(false),
        SubAbciRequest::BasicVerifyTX(txaux) => {
            SubAbciResponse::BasicVerifyTX(verify_in_place(&txaux, NETWORK_ID))
        }
        SubAbciRequest::FullVerifyTX(inputs, block_time, txaux) => {
            SubAbciResponse::FullVerifyTX(verify_with_storage(&txaux, inputs, block_time))
        }
    };
    send_bincode(&resp, stream)
}

pub fn handle_stream(stream: &mut TcpStream) {
    loop {
        if let Some(request) = read_bincode::<SubAbciRequest>(stream) {
            respond(request, stream).expect("failed to write response");
        } else {
            break;
        };
    }
}
