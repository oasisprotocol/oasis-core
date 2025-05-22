//! Various parsing utilities.
use std::{borrow::Cow, convert::TryInto, mem};

use chrono::prelude::*;
use mbedtls::x509;

use super::Error;

pub trait TakePrefix: Sized {
    fn take_prefix(&mut self, mid: usize) -> Result<Self, Error>;
}

impl<T> TakePrefix for &[T] {
    fn take_prefix(&mut self, mid: usize) -> Result<Self, Error> {
        if let (Some(prefix), Some(rest)) = (self.get(..mid), self.get(mid..)) {
            *self = rest;
            Ok(prefix)
        } else {
            Err(Error::QuoteParseError(
                "unexpected end of quote".to_string(),
            ))
        }
    }
}

impl<T: Clone> TakePrefix for Cow<'_, [T]> {
    fn take_prefix(&mut self, mid: usize) -> Result<Self, Error> {
        if mid <= self.len() {
            match *self {
                Cow::Borrowed(ref mut slice) => slice.take_prefix(mid).map(Cow::Borrowed),
                Cow::Owned(ref mut vec) => {
                    let rest = vec.split_off(mid);
                    Ok(Cow::Owned(mem::replace(vec, rest)))
                }
            }
        } else {
            Err(Error::QuoteParseError(
                "unexpected end of quote".to_string(),
            ))
        }
    }
}

impl TakePrefix for &str {
    fn take_prefix(&mut self, mid: usize) -> Result<Self, Error> {
        if let (Some(prefix), Some(rest)) = (self.get(..mid), self.get(mid..)) {
            *self = rest;
            Ok(prefix)
        } else {
            Err(Error::QuoteParseError(
                "unexpected end of quote".to_string(),
            ))
        }
    }
}

impl TakePrefix for Cow<'_, str> {
    fn take_prefix(&mut self, mid: usize) -> Result<Self, Error> {
        if mid <= self.len() {
            match *self {
                Cow::Borrowed(ref mut slice) => slice.take_prefix(mid).map(Cow::Borrowed),
                Cow::Owned(ref mut vec) => {
                    let rest = vec.split_off(mid);
                    Ok(Cow::Owned(mem::replace(vec, rest)))
                }
            }
        } else {
            Err(Error::QuoteParseError(
                "unexpected end of quote".to_string(),
            ))
        }
    }
}

/// Callback for X509 certificate verification at the given timestamp.
pub fn x509_custom_ts_verify_cb(ts: DateTime<Utc>) -> impl x509::VerifyCallback {
    move |cert: &x509::Certificate,
          _depth: i32,
          err: &mut x509::VerifyError|
          -> Result<(), mbedtls::Error> {
        err.set(
            x509::VerifyError::CERT_EXPIRED,
            ts.naive_utc()
                > cert
                    .not_after()?
                    .try_into()
                    .map_err(|_| mbedtls::Error::X509InvalidDate)?,
        );
        err.set(
            x509::VerifyError::CERT_FUTURE,
            ts.naive_utc()
                < cert
                    .not_before()?
                    .try_into()
                    .map_err(|_| mbedtls::Error::X509InvalidDate)?,
        );
        Ok(())
    }
}
