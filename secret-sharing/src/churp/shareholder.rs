//! CHURP shareholder.

use anyhow::Result;
use group::ff::Field;

use crate::suites::FieldDigest;

use super::Error;

/// Domain separation tag for encoding shareholder identifiers.
const SHAREHOLDER_ENC_DST: &[u8] = b"shareholder";

/// Shareholder identifier.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ShareholderId(pub [u8; 32]);

impl ShareholderId {
    /// Encodes the given shareholder ID to a non-zero element of the prime field.
    pub fn encode<H: FieldDigest>(&self) -> Result<H::Output> {
        let s = H::hash_to_field(&self.0[..], SHAREHOLDER_ENC_DST)
            .map_err(|_| Error::ShareholderEncodingFailed)?;

        if s.is_zero().into() {
            return Err(Error::ZeroValueShareholder.into());
        }

        Ok(s)
    }
}
