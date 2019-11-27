//! Mnemonic wrapper
use std::fmt;
use zeroize::Zeroize;

use bip39::{Language, MnemonicType, Seed};
use secstr::SecUtf8;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};

use client_common::{ErrorKind, Result, ResultExt};

const MNEMONIC_TYPE: MnemonicType = MnemonicType::Words24;
const MNEMONIC_LANGUAGE: Language = Language::English;

/// Mnemonic wrapped in secures string
pub struct Mnemonic(bip39::Mnemonic);

impl Serialize for Mnemonic {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.phrase())
    }
}

impl<'de> Deserialize<'de> for Mnemonic {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Mnemonic::from_str(&String::deserialize(deserializer)?)
            .map_err(|e| de::Error::custom(format!("{}", e)))
    }
}

impl Mnemonic {
    /// Generate and returns mnemonic words
    #[allow(clippy::new_without_default)]
    #[inline]
    pub fn new() -> Self {
        let mnemonic = bip39::Mnemonic::new(MNEMONIC_TYPE, MNEMONIC_LANGUAGE);

        Mnemonic(mnemonic)
    }

    /// Create Mnemonic from words in secure string
    #[inline]
    pub fn from_secstr(words: &SecUtf8) -> Result<Self> {
        Mnemonic::from_str(words.unsecure())
    }

    /// Create Mnemonic from words in string literal
    #[inline]
    fn from_str(words: &str) -> Result<Self> {
        let mnemonic = bip39::Mnemonic::from_phrase(words, MNEMONIC_LANGUAGE)
            .chain(|| (ErrorKind::DeserializationError, "Invalid mnemonic phrase"))?;

        Ok(Mnemonic(mnemonic))
    }

    /// Returns mnemonic phrase as secure string
    #[inline]
    pub fn phrase(&self) -> SecUtf8 {
        SecUtf8::from(self.0.phrase())
    }

    /// Returns mnemonic phrase as string literal
    #[inline]
    pub fn unsecure_phrase(&self) -> &str {
        self.0.phrase()
    }

    /// Returns the seed from the mnemonic words as byte slice
    #[inline]
    pub fn seed(&self) -> Vec<u8> {
        // TODO: advanced/optional recovery" seeding option
        // give salt as another argument, make default as ""
        Seed::new(&self.0, "").as_bytes().to_vec()
    }

    // TODO: Implement zeroize for bip39::Mnemonic phrase and entropy
    // Right now only the phrase can be zero out
    /// Take ownership and zeroize
    #[inline]
    pub fn zeroize(self) {
        self.0.into_phrase().zeroize()
    }
}

impl AsRef<str> for Mnemonic {
    fn as_ref(&self) -> &str {
        self.unsecure_phrase()
    }
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "***SECRET***")
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "***SECRET***")
    }
}

#[cfg(test)]
mod mnemonic_tests {
    use super::*;

    mod new {
        use super::*;

        #[test]
        fn should_generate_valid_mnemonic() {
            let mnemonic = Mnemonic::new();

            assert!(
                bip39::Mnemonic::validate(mnemonic.unsecure_phrase(), MNEMONIC_LANGUAGE).is_ok()
            );
        }

        #[test]
        fn should_generate_unique_mnemonic() {
            let mnemonic_1 = Mnemonic::new();
            let mnemonic_2 = Mnemonic::new();

            assert_mnemonic_are_different(&mnemonic_1, &mnemonic_2);
        }

        #[test]
        fn should_generate_24_word() {
            let mnemonic = Mnemonic::new();
            let word_count = mnemonic.unsecure_phrase().split(' ').count();

            assert_eq!(24, word_count);
        }
    }

    mod from_secstr {
        use super::*;

        #[test]
        fn should_throw_error_when_mnemonic_is_invalid() {
            let mnemonic = SecUtf8::from("hello from rust");

            let result = Mnemonic::from_secstr(&mnemonic);
            assert!(result.is_err());
            assert_eq!(
                ErrorKind::DeserializationError,
                result.expect_err("Invalid mnemonic words").kind()
            );
        }

        #[test]
        fn should_return_mnemonic() {
            let words = SecUtf8::from("point shiver hurt flight fun online hub antenna engine pave chef fantasy front interest poem accident catch load frequent praise elite pet remove used");

            let mnemonic = Mnemonic::from_secstr(&words.clone())
                .expect("should deserialize mnemonic words from secstr");

            assert_eq!(words, mnemonic.phrase());
        }
    }

    #[test]
    fn test_deserialize_error() {
        let invalid_mnemonic_json = "\"hello from rust\"";
        let deserialize_result = serde_json::from_str::<Mnemonic>(invalid_mnemonic_json);

        assert!(deserialize_result.is_err());
        assert!(format!("{}", deserialize_result.unwrap_err()).contains("Invalid mnemonic phrase"));
    }

    #[test]
    fn test_serailize_deserialize_flow() {
        let mnemonic = Mnemonic::new();

        let expected_mnemonic_json = format!("\"{}\"", mnemonic.unsecure_phrase());
        assert_eq!(
            expected_mnemonic_json,
            serde_json::to_string(&mnemonic).expect("should serialize mnemonic to json")
        );

        let deserialized_mnemonic = serde_json::from_str::<Mnemonic>(&expected_mnemonic_json)
            .expect("should deserialize mnemonic from json");
        assert_mnemonic_are_same(&mnemonic, &deserialized_mnemonic);
    }

    #[test]
    fn should_display_as_secret() {
        let mnemonic = Mnemonic::new();

        assert_eq!("***SECRET***", format!("{}", mnemonic));
    }

    #[test]
    fn should_debug_as_secret() {
        let mnemonic = Mnemonic::new();

        assert_eq!("***SECRET***", format!("{:#?}", mnemonic));
    }

    fn assert_mnemonic_are_same(mnemonic: &Mnemonic, other: &Mnemonic) {
        assert_eq!(mnemonic.phrase(), other.phrase());
    }

    fn assert_mnemonic_are_different(mnemonic: &Mnemonic, other: &Mnemonic) {
        assert_ne!(mnemonic.phrase(), other.phrase());
    }
}
