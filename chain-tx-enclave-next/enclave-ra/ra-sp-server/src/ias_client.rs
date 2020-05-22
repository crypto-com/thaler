use ra_common::{sp::AttestationEvidence, AttestationReport};
use reqwest::blocking::Client;
use thiserror::Error;

/// Client used for connecting to Intel Attestation Service (IAS)
pub struct IasClient {
    /// IAS API Key
    ias_key: String,
    /// HTTP client
    http_client: Client,
    /// Base URI of intel attestation service (IAS)
    ias_base_uri: String,
    /// API path to get SigRL from IAS
    ias_sig_rl_path: String,
    /// API path to get attestation report from IAS
    ias_report_path: String,
}

impl IasClient {
    /// Creates a new instance of IAS client
    pub fn new(
        ias_key: String,
        ias_base_uri: String,
        ias_sig_rl_path: String,
        ias_report_path: String,
    ) -> Self {
        let http_client = Client::new();

        Self {
            ias_key,
            http_client,
            ias_base_uri,
            ias_sig_rl_path,
            ias_report_path,
        }
    }

    /// Gets SigRL (Signature revocation list) from IAS
    pub fn get_sig_rl(&self, gid: [u8; 4]) -> Result<Option<Vec<u8>>, IasClientError> {
        let url = format!(
            "{}{}{:02x}{:02x}{:02x}{:02x}",
            self.ias_base_uri, self.ias_sig_rl_path, gid[0], gid[1], gid[2], gid[3]
        );

        let response = self
            .http_client
            .get(&url)
            .header("Ocp-Apim-Subscription-Key", &self.ias_key)
            .send()?
            .error_for_status()?;

        // Return error if response status code is not 200
        let status = response.status().as_u16();
        if 200 != status {
            return Err(IasClientError::InvalidResponseStatus(status));
        }

        // Return `None` if `Content-Length` is `0`
        let content_length = response.content_length().unwrap_or_default();
        if 0 == content_length {
            return Ok(None);
        }

        // Response body contains base64 encoded SigRL
        let base64_encoded_sig_rl = response.text()?;

        if base64_encoded_sig_rl.is_empty() {
            return Ok(None);
        }

        base64::decode(&base64_encoded_sig_rl)
            .map(Some)
            .map_err(Into::into)
    }

    /// Verifies given attestation evidence and generates a new attestation verification report
    pub fn verify_attestation_evidence(
        &self,
        quote: &[u8],
    ) -> Result<AttestationReport, IasClientError> {
        let evidence = AttestationEvidence::from_quote(quote);

        let url = format!("{}{}", self.ias_base_uri, self.ias_report_path);

        let response = self
            .http_client
            .post(&url)
            .header("Ocp-Apim-Subscription-Key", &self.ias_key)
            .json(&evidence)
            .send()?
            .error_for_status()?;

        // Return error if response status code is not 200
        let status = response.status().as_u16();
        if 200 != status {
            return Err(IasClientError::InvalidResponseStatus(status));
        }

        // Extract signature
        let encoded_signature = response
            .headers()
            .get("X-IASReport-Signature")
            .ok_or_else(|| IasClientError::MissingSignature)?;

        if encoded_signature.is_empty() {
            return Err(IasClientError::MissingSignature);
        }

        let signature = base64::decode(&encoded_signature)?;

        // Extract signing certificate
        let signing_cert = response
            .headers()
            .get("X-IASReport-Signing-Certificate")
            .ok_or_else(|| IasClientError::MissingSignature)?
            .as_ref()
            .to_vec();

        // Parse attestation verification report body
        let body = response.bytes()?.to_vec();

        Ok(AttestationReport {
            body,
            signature,
            signing_cert,
        })
    }
}

#[derive(Debug, Error)]
pub enum IasClientError {
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("Invalid response status code: {0}")]
    InvalidResponseStatus(u16),
    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("JSON encoding/decoding error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Missing signature in attestation verification report")]
    MissingSignature,
}
