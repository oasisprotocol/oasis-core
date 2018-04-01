//! Enclave interface.
use sgx_types::*;
use sgx_urts::SgxEnclave;

use ekiden_common::error::{Error, Result};

/// Ekiden enclave.
pub struct Enclave {
    /// Internal enclave instance.
    enclave: SgxEnclave,
}

impl Enclave {
    /// Initializes a new enclave.
    pub fn new(filename: &str) -> Result<Self> {
        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;

        // Initialize enclave.
        // TODO: Handle debug vs. release mode.
        let debug = 1;
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
            misc_select: 0,
        };

        let enclave = match SgxEnclave::create(
            filename,
            debug,
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        ) {
            Ok(enclave) => enclave,
            Err(_) => {
                return Err(Error::new("Failed to launch enclave"));
            }
        };

        Ok(Enclave { enclave: enclave })
    }

    /// Return enclave identifier.
    pub fn get_id(&self) -> sgx_enclave_id_t {
        self.enclave.geteid()
    }
}
