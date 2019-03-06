extern crate serde;
#[macro_use]
extern crate serde_derive;
use bincode::{deserialize, serialize_into, serialized_size};
use integer_encoding::VarInt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

#[derive(Serialize, Deserialize, Debug)]
pub enum SubAbciRequest {
    InitChain(u8),
    // VerifyTX(TxAux)
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SubAbciResponse {
    InitChain(bool),
    // VerifyTX(TxAux)
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
