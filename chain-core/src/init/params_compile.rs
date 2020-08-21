use ra_client::DEFAULT_EXPIRATION_SECS;

/// Timeout (in seconds) for MLS handshake commit
pub const MLS_COMMIT_TIMEOUT_SECS: u64 = 60;

/// Timeout (in seconds) for MLS handshake message NACK
pub const MLS_MESSAGE_NACK_TIMEOUT_SECS: u64 = MLS_COMMIT_TIMEOUT_SECS;

/// Time (in seconds) after which, the keypackage for a node will be considered as expired
pub const KEYPACKAGE_EXPIRATION_SECS: u64 = DEFAULT_EXPIRATION_SECS as u64;

/// Time (in seconds) after which, the keypackage for a node is allowed to update, keypackage_update_secs < keypackage_expiration_secs
pub const KEYPACKAGE_UPDATE_SECS: u64 = KEYPACKAGE_EXPIRATION_SECS / 3;
