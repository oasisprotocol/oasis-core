use std::{
    any::Any,
    sync::{Mutex, Once},
};

use anyhow::Result;
use lazy_static::lazy_static;

use super::{signers::SignedData, TrustedSigners};

lazy_static! {
    /// Set of trusted signers.
    static ref TRUSTED_SIGNERS: Mutex<TrustedSigners> = Mutex::new(TrustedSigners::default());

    /// Initializes the global TRUSTED_SIGNERS only once.
    static ref INIT_TRUSTED_SIGNERS_ONCE: Once = Once::new();
}

/// Sets the global set of trusted signers.
///
/// Changing the set of signers after the first call is not possible.
pub fn set_trusted_signers(signers: TrustedSigners) {
    INIT_TRUSTED_SIGNERS_ONCE.call_once(|| {
        *TRUSTED_SIGNERS.lock().unwrap() = signers;
    });
}

/// Verify that data has valid signatures and that enough of them are from
/// the global set of trusted signers.
pub fn verify_data_and_trusted_signers<P: Any>(signed_data: &impl SignedData<P>) -> Result<&P> {
    TRUSTED_SIGNERS.lock().unwrap().verify(signed_data)
}
