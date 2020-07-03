use chain_core::init::coin::{Coin, CoinError};
use mls::keypackage;

#[derive(thiserror::Error, Debug)]
pub enum TxError {
    #[error("deserialize TxAux failed: {0}")]
    DeserializeTx(#[from] parity_scale_codec::Error),
    #[error("enclave tx validation failed: {0}")]
    Enclave(#[from] chain_tx_validation::Error),
    #[error("public tx process failed: {0}")]
    Public(#[from] PublicTxError),
    #[error("FIXME/WIP payload for MLS handshake (not yet supported)")]
    WIPMLSData,
}

#[derive(thiserror::Error, Debug)]
pub enum PublicTxError {
    #[error("public tx wrong chain_hex_id")]
    WrongChainHexId,
    #[error("public tx unsupported version")]
    UnsupportedVersion,
    #[error("verify staking witness failed: {0}")]
    StakingWitnessVerify(#[from] secp256k1::Error),
    #[error("staking witness and address don't match")]
    StakingWitnessNotMatch,
    #[error("tx nonce don't match staking state")]
    IncorrectNonce,
    #[error("unjail tx process failed: {0}")]
    Unjail(#[from] UnjailError),
    #[error("node join tx process failed: {0}")]
    NodeJoin(#[from] NodeJoinError),
    #[error("unbond tx process failed: {0}")]
    Unbond(#[from] UnbondError),
}

#[derive(thiserror::Error, Debug)]
pub enum UnjailError {
    #[error("the staking address is not jailed")]
    NotJailed,
    #[error("the jail duration is not reached yet")]
    JailTimeNotExpired,
}

#[derive(thiserror::Error, Debug)]
pub enum NodeJoinError {
    #[error("bonded coins not enough to become validator")]
    BondedNotEnough,
    #[error("validator address already exists")]
    DuplicateValidatorAddress,
    #[error("the staking address is already active")]
    AlreadyJoined,
    #[error("the staking address is jailed")]
    IsJailed,
    #[error("the used_validator_addresses queue is full")]
    UsedValidatorAddrFull,
    #[error("key package decode failed")]
    KeyPackageDecodeError,
    #[error("invalid key package: {0}")]
    KeyPackageVerifyError(#[from] keypackage::Error),
    #[error("FIXME: WIP -- community node not yet supported")]
    WIPNotValidator,
}

#[derive(thiserror::Error, Debug)]
pub enum WithdrawError {
    #[error("unbonded amount {0} not equal to desired amount: {0}")]
    UnbondedSanityCheck(Coin, Coin),
    #[error("still in unbonding period")]
    InUnbondingPeriod,
    #[error("the staking address is jailed")]
    IsJailed,
}

#[derive(thiserror::Error, Debug)]
pub enum UnbondError {
    #[error("nonce value don't match")]
    NonceNotMatch,
    #[error("coin error in unbond tx: {0}")]
    CoinError(#[from] CoinError),
    #[error("the staking address is jailed")]
    IsJailed,
    #[error("the value of tx is zero")]
    ZeroValue,
}

#[derive(thiserror::Error, Debug)]
pub enum DepositError {
    #[error("coin error in deposit tx: {0}")]
    CoinError(#[from] CoinError),
    #[error("the staking address is jailed")]
    IsJailed,
}
