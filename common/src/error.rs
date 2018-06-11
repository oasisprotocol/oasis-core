//! Error types used in Ekiden.
use std::{error, fmt, result};

/// A custom result type which uses `Error` to avoid the need to repeat the
/// error type over and over again.
pub type Result<T> = result::Result<T, Error>;

/// Error type for use in Ekiden crates.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Error {
    /// Error message.
    pub message: String,
}

impl Error {
    /// Construct a new error instance.
    pub fn new<S: Into<String>>(message: S) -> Self {
        Error {
            message: message.into(),
        }
    }

    /// A short description of the error.
    pub fn description(&self) -> &str {
        &self.message
    }
}

impl<T: error::Error> From<T> for Error {
    fn from(error: T) -> Self {
        Self::new(format!("{:?}", error))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
