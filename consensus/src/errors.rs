use std;
use std::string;

use hyper;

#[derive(Debug)]
pub enum Error {
    HyperError(hyper::Error),
    HyperUriError(hyper::error::UriError),
    StringError(string::FromUtf8Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match self {
            &Error::HyperError(ref e) => e.description(),
            &Error::HyperUriError(ref e) => e.description(),
            &Error::StringError(ref e) => e.description(),
        }
    }
    fn cause(&self) -> Option<&std::error::Error> {
        match self {
            &Error::HyperError(ref e) => Some(e),
            &Error::HyperUriError(ref e) => Some(e),
            &Error::StringError(ref e) => Some(e),
        }
    }
}

impl From<hyper::Error> for Error {
    fn from(error: hyper::Error) -> Self {
        Error::HyperError(error)
    }
}

impl From<hyper::error::UriError> for Error {
    fn from(error: hyper::error::UriError) -> Self {
        Error::HyperUriError(error)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(error: string::FromUtf8Error) -> Self {
        Error::StringError(error)
    }
}
