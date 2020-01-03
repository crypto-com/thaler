use std::fmt;

pub enum Error {
    HexIdMisMatch,
    EmptySealedLog,
    EmptyRequestAccount,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Error::*;
        match self {
            HexIdMisMatch => write!(f, "hex id mismatch"),
            EmptySealedLog => write!(f, "sealed log is empty"),
            EmptyRequestAccount => write!(f, "request account is empty"),
        }
    }
}
