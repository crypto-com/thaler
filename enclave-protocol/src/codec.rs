use std::{
    convert::TryInto,
    io::{self, Read, Write},
    vec,
    vec::Vec,
};

use parity_scale_codec::{Decode, Encode};

/// Trait for writing length encoded valus to a stream
pub trait StreamWrite {
    fn write_to<W: Write>(&self, writer: W) -> io::Result<usize>;
}

/// Trait for reading values written using `StreamWrite`
pub trait StreamRead: Decode {
    fn read_from<R: Read>(reader: R) -> io::Result<Self>;
}

impl<T: Encode> StreamWrite for T {
    fn write_to<W: Write>(&self, mut writer: W) -> io::Result<usize> {
        let mut bytes = self.encode();
        let mut to_send = Vec::with_capacity(
            bytes
                .len()
                .checked_add(4)
                .expect("Bytes to send cannot fit in a `Vec`"),
        );

        let size: u32 = bytes
            .len()
            .try_into()
            .expect("Bytes to send cannot fit into u64");

        to_send.extend(&size.to_le_bytes());
        to_send.append(&mut bytes);

        writer.write(&to_send)
    }
}

impl<T: Decode> StreamRead for T {
    fn read_from<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut size = [0u8; 4];
        reader.read_exact(&mut size)?;
        let size: usize = u32::from_le_bytes(size)
            .try_into()
            .expect("Too many bytes! Cannot read.");

        let mut buffer = vec![0; size];
        reader.read_exact(&mut buffer)?;

        Self::decode(&mut buffer.as_slice()).map_err(|_| io::ErrorKind::Other.into())
    }
}
