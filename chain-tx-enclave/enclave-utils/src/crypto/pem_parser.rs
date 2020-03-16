// modified from https://docs.rs/pem-parser/0.1.1/src/pem_parser/lib.rs.html#1-18
use base64::{decode, DecodeError};
use regex::Regex;

const REGEX: &'static str = r"(-----BEGIN .*-----\n)((?:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)*\n)+)(-----END .*-----)";

/// Parse the contents of a PEM file and return a DER-serialized byte slice.
/// This won't work if `pem_file_contents` contains more than a single key / certificate.
pub fn pem_to_der(pem_file_contents: &str) -> Result<Vec<u8>, DecodeError> {
    let re = Regex::new(REGEX).unwrap();
    let contents_without_headers = re.replace(pem_file_contents, "$2");
    let base64_body = contents_without_headers.replace("\n", "");
    decode(&base64_body)
}
