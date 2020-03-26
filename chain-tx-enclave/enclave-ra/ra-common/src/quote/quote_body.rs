use std::convert::TryInto;

const QUOTE_BODY_LEN: usize = 48;

/// Body of quote
#[derive(Debug)]
pub struct QuoteBody {
    /// Version of the quote structure
    pub version: u16,
    /// Signature type of quote
    pub sig_type: u16,
    /// ID of the Intel EPID group of the platform belongs to
    pub gid: u32,
    /// Security version number of Quoting Enclave
    pub qe_svn: u16,
    /// Security version number of PCE
    pub pce_svn: u16,
    /// EPID basename used in quote
    pub basename: [u8; 32],
}

impl QuoteBody {
    pub fn try_copy_from(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != QUOTE_BODY_LEN {
            return None;
        }

        let mut pos: usize = 0;
        let mut take = |n: usize| -> Option<&[u8]> {
            if n > 0 && bytes.len() >= pos + n {
                let ret = &bytes[pos..pos + n];
                pos += n;
                Some(ret)
            } else {
                None
            }
        };

        // off 0, size 2
        let version = u16::from_le_bytes(take(2)?.try_into().ok()?);

        // off 2, size 2
        let sig_type = u16::from_le_bytes(take(2)?.try_into().ok()?);

        // off 4, size 4
        let gid = u32::from_le_bytes(take(4)?.try_into().ok()?);

        // off 8, size 2
        let qe_svn = u16::from_le_bytes(take(2)?.try_into().ok()?);

        // off 10, size 2
        let pce_svn = u16::from_le_bytes(take(2)?.try_into().ok()?);

        // off 12, size 4
        let _reserved = take(4)?;

        // off 16, size 32
        let basename = take(32)?.try_into().ok()?;

        if pos != bytes.len() {
            return None;
        }

        Some(Self {
            version,
            sig_type,
            gid,
            qe_svn,
            pce_svn,
            basename,
        })
    }
}
