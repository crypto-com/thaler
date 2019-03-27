use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use digest::Digest;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use secp256k1::constants::{COMPACT_SIGNATURE_SIZE, PUBLIC_KEY_SIZE};
use std::cmp;
use std::mem;

/// Generic merkle tree
pub mod merkle;
pub const HASH_SIZE_256: usize = 32;

/// Calculates 256-bit crypto hash
pub fn hash256<D: Digest>(data: &[u8]) -> H256 {
    let mut hasher = D::new();
    hasher.input(data);
    let mut out = [0u8; HASH_SIZE_256];
    out.copy_from_slice(&hasher.result()[..]);
    out.into()
}

/// Seconds since UNIX epoch
#[derive(Debug, PartialEq, Eq, Clone, Copy, Ord, PartialOrd)]
pub struct Timespec(i64);

impl From<i64> for Timespec {
    fn from(v: i64) -> Self {
        Timespec(v)
    }
}

impl Encodable for Timespec {
    fn rlp_append(&self, s: &mut RlpStream) {
        let mut bs = [0u8; mem::size_of::<i64>()];
        bs.as_mut()
            .write_i64::<LittleEndian>(self.0)
            .expect("Unable to write Timespec");
        s.encoder().encode_value(&bs[..]);
    }
}

impl Decodable for Timespec {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        rlp.decoder().decode_value(|mut bytes| match bytes.len() {
            l if l == mem::size_of::<i64>() => {
                let r = bytes
                    .read_i64::<LittleEndian>()
                    .map_err(|_| DecoderError::Custom("failed to read i64"))?;
                Ok(Timespec(r))
            }
            l if l < mem::size_of::<i64>() => Err(DecoderError::RlpIsTooShort),
            _ => Err(DecoderError::RlpIsTooBig),
        })
    }
}

#[macro_export]
macro_rules! impl_encodable_for_hash {
    ($name: ident) => {
        impl Encodable for $name {
            fn rlp_append(&self, s: &mut RlpStream) {
                s.encoder().encode_value(&self.0[..]);
            }
        }
    };
}

#[macro_export]
macro_rules! impl_decodable_for_hash {
    ($name: ident, $size: expr) => {
        impl Decodable for $name {
            fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
                rlp.decoder()
                    .decode_value(|bytes| match bytes.len().cmp(&$size) {
                        cmp::Ordering::Less => Err(DecoderError::RlpIsTooShort),
                        cmp::Ordering::Greater => Err(DecoderError::RlpIsTooBig),
                        cmp::Ordering::Equal => {
                            let mut t = [0u8; $size];
                            t.copy_from_slice(bytes);
                            Ok($name(t))
                        }
                    })
            }
        }
    };
}

macro_rules! construct_fixed_hash {
	( $(#[$attr:meta])* $visibility:vis struct $name:ident ( $n_bytes:expr ); ) => {
		#[repr(C)]
		$(#[$attr])*
		$visibility struct $name ([u8; $n_bytes]);

		impl From<[u8; $n_bytes]> for $name {
			/// Constructs a hash type from the given bytes array of fixed length.
			///
			/// # Note
			///
			/// The given bytes are interpreted in big endian order.
			#[inline]
			fn from(bytes: [u8; $n_bytes]) -> Self {
				$name(bytes)
			}
		}

		impl<'a> From<&'a [u8; $n_bytes]> for $name {
			/// Constructs a hash type from the given reference
			/// to the bytes array of fixed length.
			///
			/// # Note
			///
			/// The given bytes are interpreted in big endian order.
			#[inline]
			fn from(bytes: &'a [u8; $n_bytes]) -> Self {
				$name(*bytes)
			}
		}

		impl<'a> From<&'a mut [u8; $n_bytes]> for $name {
			/// Constructs a hash type from the given reference
			/// to the mutable bytes array of fixed length.
			///
			/// # Note
			///
			/// The given bytes are interpreted in big endian order.
			#[inline]
			fn from(bytes: &'a mut [u8; $n_bytes]) -> Self {
				$name(*bytes)
			}
		}

		impl From<$name> for [u8; $n_bytes] {
			#[inline]
			fn from(s: $name) -> Self {
				s.0
			}
		}

		impl AsRef<[u8]> for $name {
			#[inline]
			fn as_ref(&self) -> &[u8] {
				self.as_bytes()
			}
		}

		impl AsMut<[u8]> for $name {
			#[inline]
			fn as_mut(&mut self) -> &mut [u8] {
				self.as_bytes_mut()
			}
		}
		impl $name {
			/// Returns a new fixed hash where all bits are set to the given byte.
			#[inline]
			pub fn repeat_byte(byte: u8) -> $name {
				$name([byte; $n_bytes])
			}

			/// Returns a new zero-initialized fixed hash.
			#[inline]
			pub fn zero() -> $name {
				$name::repeat_byte(0u8)
			}

			/// Returns the size of this hash in bytes.
			#[inline]
			pub fn len_bytes() -> usize {
				$n_bytes
			}

			/// Extracts a byte slice containing the entire fixed hash.
			#[inline]
			pub fn as_bytes(&self) -> &[u8] {
				&self.0
			}

			/// Extracts a mutable byte slice containing the entire fixed hash.
			#[inline]
			pub fn as_bytes_mut(&mut self) -> &mut [u8] {
				&mut self.0
			}
        }

        impl std::marker::Copy for $name {}

        impl std::clone::Clone for $name {
            fn clone(&self) -> $name {
                let mut ret = $name::zero();
                ret.0.copy_from_slice(&self.0);
                ret
            }
        }

		impl std::cmp::PartialEq for $name {
			#[inline]
			fn eq(&self, other: &Self) -> bool {
				self.0.eq(&other.0[..])
			}
		}

        impl std::cmp::Eq for $name {}

		impl std::cmp::Ord for $name {
			fn cmp(&self, other: &Self) -> std::cmp::Ordering {
				self.0.cmp(&other.0)
			}
		}

		impl std::cmp::PartialOrd for $name {
			fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
				Some(self.cmp(other))
			}
		}

		impl std::fmt::LowerHex for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
				if f.alternate() {
					write!(f, "0x")?;
				}
				for i in &self.0[..] {
					write!(f, "{:02x}", i)?;
				}
				Ok(())
			}
		}

		impl std::fmt::Debug for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
				write!(f, "{:#x}", self)
			}
		}

		impl std::hash::Hash for $name {
			fn hash<H>(&self, state: &mut H) where H: std::hash::Hasher {
				state.write(&self.0);
				state.finish();
			}
		}

		impl<I> std::ops::Index<I> for $name
		where
			I: std::slice::SliceIndex<[u8]>
		{
			type Output = I::Output;

			#[inline]
			fn index(&self, index: I) -> &I::Output {
				&self.as_bytes()[index]
			}
		}

    }
}

construct_fixed_hash! {pub struct H256(HASH_SIZE_256);}
construct_fixed_hash! {pub struct H264(HASH_SIZE_256 + 1);}
construct_fixed_hash! {pub struct H512(2 * HASH_SIZE_256);}

impl_encodable_for_hash!(H256);
impl_decodable_for_hash!(H256, HASH_SIZE_256);
impl_encodable_for_hash!(H264);
impl_decodable_for_hash!(H264, PUBLIC_KEY_SIZE);
impl_encodable_for_hash!(H512);
impl_decodable_for_hash!(H512, COMPACT_SIGNATURE_SIZE);
