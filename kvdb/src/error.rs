use std::fmt;

use failure::{Backtrace, Context, Fail};

/// Errors in Crypto.com `kvdb`
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

/// Error kinds in Crypto.com `kvdb`
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "Column not found")]
    ColumnNotFound,
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        *self.inner.get_context()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}
