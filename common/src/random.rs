//! Obtain random bytes in and outside enclaves.
#[cfg(not(target_env = "sgx"))]
use rand::{OsRng, Rng};

#[cfg(target_env = "sgx")]
use sgx_trts;

use super::error::{Error, Result};

/// Fill destination type with random bytes.
#[cfg(target_env = "sgx")]
pub fn get_random_bytes(destination: &mut [u8]) -> Result<()> {
    match sgx_trts::trts::rsgx_read_rand(destination) {
        Ok(_) => {}
        _ => return Err(Error::new("Random bytes failed")),
    }

    Ok(())
}

/// Fill destination type with random bytes.
#[cfg(not(target_env = "sgx"))]
pub fn get_random_bytes(destination: &mut [u8]) -> Result<()> {
    let mut rng = match OsRng::new() {
        Ok(rng) => rng,
        _ => return Err(Error::new("Random bytes failed")),
    };

    rng.fill_bytes(destination);

    Ok(())
}
