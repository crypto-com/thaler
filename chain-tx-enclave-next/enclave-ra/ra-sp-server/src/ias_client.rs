use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use thiserror::Error;

use ra_common::{sp::AttestationEvidence, AttestationReport};

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
        let signature = extract_signature(response.headers())?;

        // Extract signing certificate
        let signing_cert = extract_signing_certificate(response.headers())?;

        // Parse attestation verification report body
        let body = response.bytes()?.to_vec();

        Ok(AttestationReport {
            body,
            signature,
            signing_cert,
        })
    }
}

fn extract_signing_certificate(response_headers: &HeaderMap) -> Result<Vec<u8>, IasClientError> {
    let urlencoded_signing_certificate = response_headers
        .get("X-IASReport-Signing-Certificate")
        .ok_or_else(|| IasClientError::MissingSigningCertificate)?
        .as_ref();
    let signing_certificate = percent_encoding::percent_decode(urlencoded_signing_certificate)
        .decode_utf8()
        .map_err(IasClientError::SigningCertificateDecodeError)?;
    Ok(signing_certificate.as_bytes().to_vec())
}

fn extract_signature(response_headers: &HeaderMap) -> Result<Vec<u8>, IasClientError> {
    let encoded_signature = response_headers
        .get("X-IASReport-Signature")
        .ok_or_else(|| IasClientError::MissingSignature)?;
    if encoded_signature.is_empty() {
        return Err(IasClientError::MissingSignature);
    }
    Ok(base64::decode(&encoded_signature)?)
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
    #[error("Missing signing certificate in attestation verification report")]
    MissingSigningCertificate,
    #[error("Signing certificate decode error")]
    SigningCertificateDecodeError(#[source] std::str::Utf8Error),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use reqwest::header::{HeaderMap, HeaderValue};

    use crate::ias_client::{extract_signature, extract_signing_certificate, IasClientError};

    #[test]
    fn test_extract_signing_certificate() {
        let certificate_context = "-----BEGIN%20CERTIFICATE-----%0AMIIEoT<...certificate_chain...>GMnX%0A-----END%20CERTIFICATE-----%0A";
        let mut headers = HeaderMap::new();
        headers.append(
            "X-IASReport-Signing-Certificate",
            HeaderValue::from_str(certificate_context).unwrap(),
        );

        let expected = "-----BEGIN CERTIFICATE-----\nMIIEoT<...certificate_chain...>GMnX\n-----END CERTIFICATE-----\n";
        assert_eq!(
            extract_signing_certificate(&headers).unwrap(),
            expected.as_bytes().to_vec()
        );
    }

    #[test]
    fn test_extract_signing_certificate_missing_signing_certificate() {
        let headers = HeaderMap::new();
        let result = extract_signing_certificate(&headers);

        assert!(matches!(
            result.unwrap_err(),
            IasClientError::MissingSigningCertificate
        ));
    }

    #[test]
    fn test_extract_signing_certificate_signing_certificate_decode_error() {
        let certificate_context =
            "-----BEGIN%20CERTIFICATE-----%0AMIIEoT%FF%FDGMnX%0A-----END%20CERTIFICATE-----%0A";
        let mut headers = HeaderMap::new();
        headers.append(
            "X-IASReport-Signing-Certificate",
            HeaderValue::from_str(certificate_context).unwrap(),
        );
        let result = extract_signing_certificate(&headers);

        let error = result.unwrap_err();
        assert!(matches!(
            error,
            IasClientError::SigningCertificateDecodeError(_)
        ));
        assert!(error.source().is_some());
    }

    #[test]
    fn test_extract_signature() {
        let signature = "c2lnbmF0dXJl";
        let mut headers = HeaderMap::new();
        headers.append(
            "X-IASReport-Signature",
            HeaderValue::from_str(signature).unwrap(),
        );
        let result = extract_signature(&headers);

        assert_eq!(result.unwrap(), "signature".as_bytes().to_vec());
    }

    #[test]
    fn test_extract_signature_missing_signature() {
        let headers = HeaderMap::new();
        let result = extract_signature(&headers);

        assert!(matches!(
            result.unwrap_err(),
            IasClientError::MissingSignature
        ));
    }

    #[test]
    fn test_extract_signature_base64_error() {
        let signature = "base64_error";
        let mut headers = HeaderMap::new();
        headers.append(
            "X-IASReport-Signature",
            HeaderValue::from_str(signature).unwrap(),
        );
        let result = extract_signature(&headers);

        let error = result.unwrap_err();
        assert!(matches!(error, IasClientError::Base64Error(_)));
    }
}
