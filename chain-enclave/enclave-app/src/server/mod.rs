use abci_enclave_macro::get_network_id;
use abci_enclave_protocol::{read_bincode, send_bincode, Error, SubAbciRequest, SubAbciResponse};
use chain_core::init::coin::Coin;
use chain_core::tx::TxAux;
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::net::TcpStream;

const NETWORK_ID: u8 = get_network_id!();

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

fn respond(request: SubAbciRequest, stream: &mut Write) -> io::Result<()> {
    let resp = match request {
        SubAbciRequest::InitChain(chain_hex_id) if chain_hex_id == NETWORK_ID => {
            SubAbciResponse::InitChain(true)
        }
        SubAbciRequest::InitChain(_) => SubAbciResponse::InitChain(false),
        SubAbciRequest::BasicVerifyTX(txaux) => {
            SubAbciResponse::BasicVerifyTX(verify_in_place(&txaux, NETWORK_ID))
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
