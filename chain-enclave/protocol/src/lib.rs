extern crate serde;
#[macro_use]
extern crate serde_derive;
use bincode::{deserialize, serialize_into, serialized_size};
use chain_core::common::Timespec;
use chain_core::init::coin::{Coin, CoinError};
use chain_core::tx::{data::Tx, TxAux};
use integer_encoding::VarInt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, Read, Write};

/// All possible TX validation errors
#[derive(Serialize, Deserialize, Debug)]
pub enum Error {
    WrongChainHexId,
    NoInputs,
    NoOutputs,
    DuplicateInputs,
    ZeroCoin,
    InvalidSum(CoinError),
    InvalidInput,
    InputOutputDoNotMatch,
    OutputInTimelock,
    UnexpectedWitnesses,
    MissingWitnesses,
    WitnessVerificationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Error::*;
        match self {
            WrongChainHexId => write!(f, "chain hex ID does not match"),
            DuplicateInputs => write!(f, "duplicated inputs"),
            UnexpectedWitnesses => write!(f, "transaction has more witnesses than inputs"),
            MissingWitnesses => write!(f, "transaction has more inputs than witnesses"),
            NoInputs => write!(f, "transaction has no inputs"),
            NoOutputs => write!(f, "transaction has no outputs"),
            ZeroCoin => write!(f, "output with no credited value"),
            InvalidSum(ref err) => write!(f, "input or output sum error: {}", err),
            InvalidInput => write!(f, "transaction spends an invalid input"),
            InputOutputDoNotMatch => write!(f, "transaction input output coin sums don't match"),
            OutputInTimelock => write!(f, "output transaction is in timelock"),
            WitnessVerificationFailed => write!(f, "witness verification failed"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SubAbciRequest {
    InitChain(u8),
    BasicVerifyTX(TxAux),
    FullVerifyTX(Vec<Tx>, Timespec, TxAux),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SubAbciResponse {
    InitChain(bool),
    BasicVerifyTX(Result<Coin, Error>),
    FullVerifyTX(Result<(), Error>),
}

/// Parse out the varint. This code was adapted from the excellent integer-encoding crate
fn read_varint(stream: &mut Read) -> Result<i64, io::Error> {
    const BUFLEN: usize = 10;
    let mut buf = [0 as u8; BUFLEN];
    let mut i = 0;

    loop {
        if i >= BUFLEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unterminated varint",
            ));
        }
        let read = stream.read(&mut buf[i..i + 1])?;

        // EOF
        if read == 0 && i == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Reached EOF"));
        }
        if buf[i] & 0b10000000 == 0 {
            break;
        }
        i += 1;
    }
    let (result, _) = i64::decode_var(&buf[0..i + 1]);
    Ok(result)
}

pub fn read_bincode<T: DeserializeOwned>(stream: &mut Read) -> Option<T> {
    let length = read_varint(stream);
    if let Ok(amount) = length {
        let mut buf = vec![0; amount as usize];
        // TODO: refactor
        return match stream.read_exact(&mut buf) {
            Ok(_) => {
                if let Ok(request) = deserialize(&buf[..]) {
                    Some(request)
                } else {
                    None
                }
            }
            Err(_) => None,
        };
    }
    println!("69 {:?}", length);
    None
}

pub fn send_bincode<T: ?Sized + Serialize>(resp: &T, stream: &mut Write) -> io::Result<()> {
    let msg_size = serialized_size(resp).expect("failed to get serialization size") as usize;
    let varint = i64::encode_var_vec(msg_size as i64);
    let mut output = Vec::<u8>::with_capacity(msg_size);
    serialize_into(&mut output, resp).expect("failed to serialize response");
    stream.write_all(varint.as_slice())?;
    stream.write_all(output.as_slice())?;
    stream.flush()?;
    Ok(())
}
