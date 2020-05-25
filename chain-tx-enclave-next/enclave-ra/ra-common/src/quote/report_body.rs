use std::{convert::TryInto, fmt};

use super::Measurement;

const REPORT_BODY_LEN: usize = 384;

/// Report body in a quote
pub struct ReportBody {
    /// Security version number of host system's CPU
    pub cpu_svn: [u8; 16],
    /// Attributes of the enclave, for example, whether the enclave is running in debug mode
    pub attributes: [u8; 16],
    /// Measurement of the code and data in the enclave along with the enclave author's identity
    pub measurement: Measurement,
    /// Product ID of the enclave
    pub isv_prod_id: u16,
    /// Security version number of the enclave
    pub isv_svn: u16,
    /// Set of data used for communication between enclave and target enclave
    pub report_data: [u8; 64],
}

impl ReportBody {
    pub fn try_copy_from(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != REPORT_BODY_LEN {
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

        // off 48, size 16
        let cpu_svn = take(16)?.try_into().ok()?;

        // off 64, size 32
        let _reserved = take(32)?;

        // off 96, size 16
        let attributes = take(16)?.try_into().ok()?;

        // off 112, size 32
        let mr_enclave = take(32)?.try_into().ok()?;

        // off 144, size 32
        let _reserved = take(32)?;

        // off 176, size 32
        let mr_signer = take(32)?.try_into().ok()?;

        // off 208, size 96
        let _reserved = take(96)?;

        // off 304, size 2
        let isv_prod_id = u16::from_le_bytes(take(2)?.try_into().ok()?);

        // off 306, size 2
        let isv_svn = u16::from_le_bytes(take(2)?.try_into().ok()?);

        // off 308, size 60
        let _reserved = take(60)?;

        // off 368, size 64
        let mut report_data = [0u8; 64];
        let report_data_bytes = take(64)?;
        report_data.copy_from_slice(report_data_bytes);

        if pos != bytes.len() {
            return None;
        }

        Some(Self {
            cpu_svn,
            attributes,
            measurement: Measurement {
                mr_enclave,
                mr_signer,
            },
            isv_prod_id,
            isv_svn,
            report_data,
        })
    }
}

impl fmt::Debug for ReportBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReportBody")
            .field("cpu_svn", &self.cpu_svn)
            .field("attributes", &self.attributes)
            .field("measurement", &self.measurement)
            .field("isv_prod_id", &self.isv_prod_id)
            .field("isv_svn", &self.isv_svn)
            .field("report_data", &&self.report_data[..])
            .finish()
    }
}
