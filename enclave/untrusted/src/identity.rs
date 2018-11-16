use std;
use std::path::Path;
use std::sync::Arc;

use sgx_types;

use protobuf;
use protobuf::Message;

use ekiden_common::error::{Error, Result};
use ekiden_enclave_common::api;

use super::enclave::Enclave;

/// The IAS functionality that the enclave identity component needs.
pub trait IAS: Send + Sync {
    /// Get the SPID. This is needed to generate an appropriate quote.
    fn get_spid(&self) -> sgx_types::sgx_spid_t;

    /// Get the kind of quotes that this service expects. When you register for an SPID, you sign
    /// up to use a specific kind of quote signature, either linkable or non-linkable.
    fn get_quote_type(&self) -> sgx_types::sgx_quote_sign_type_t;

    /// Retrieve the signature revocation list for a given EPID group.
    fn sigrl(&self, gid: &sgx_types::sgx_epid_group_id_t) -> Vec<u8>;

    /// Verify submitted attestation evidence and create a new Attestation Verification Report.
    fn report(&self, quote: &[u8]) -> api::AvReport;
}

impl<T: ?Sized + IAS> IAS for Arc<T> {
    fn get_spid(&self) -> sgx_types::sgx_spid_t {
        IAS::get_spid(&**self)
    }

    fn get_quote_type(&self) -> sgx_types::sgx_quote_sign_type_t {
        IAS::get_quote_type(&**self)
    }

    fn sigrl(&self, gid: &sgx_types::sgx_epid_group_id_t) -> Vec<u8> {
        IAS::sigrl(&**self, gid)
    }

    fn report(&self, quote: &[u8]) -> api::AvReport {
        IAS::report(&**self, quote)
    }
}

/// Enclave identity interface.
pub trait EnclaveIdentity {
    /// Initialize the enclave identity. Load it from a file or create one if it doesn't exist.
    /// Returns the identity proof.
    fn identity_init(
        &self,
        ias: &IAS,
        saved_identity_path: Option<&Path>,
    ) -> Result<api::IdentityProof>;
}

const SEALED_DATA_CAPACITY: usize = 1024;
union SealedDataBuffer {
    sealed_data: sgx_types::sgx_sealed_data_t,
    buffer: [u8; SEALED_DATA_CAPACITY],
}

const QUOTE_CAPACITY: usize = 16 * 1024;
union QuoteBuffer {
    quote: sgx_types::sgx_quote_t,
    buffer: [u8; QUOTE_CAPACITY],
}

const PUBLIC_IDENTITY_CAPACITY: usize = 1024;

impl EnclaveIdentity for Enclave {
    /// Restore a saved identity, creating one and saving it if we don't already have one. Returns
    /// the enclave identity proof.
    fn identity_init(
        &self,
        ias: &IAS,
        saved_identity_path: Option<&Path>,
    ) -> Result<api::IdentityProof> {
        if let Ok(mut file) = std::fs::File::open(saved_identity_path.unwrap_or(Path::new(""))) {
            // Have saved identity. Load it.
            let mut saved_identity: api::SavedIdentity = protobuf::parse_from_reader(&mut file)?;
            let sealed_identity_length = saved_identity.get_sealed_identity().len();
            if sealed_identity_length > SEALED_DATA_CAPACITY {
                return Err(Error::new(format!(
                    "Saved identity is too large ({}/{})",
                    sealed_identity_length, SEALED_DATA_CAPACITY
                )));
            }
            let mut sealed_identity_buf: SealedDataBuffer = unsafe { std::mem::zeroed() };
            unsafe { &mut sealed_identity_buf.buffer[..sealed_identity_length] }
                .copy_from_slice(saved_identity.get_sealed_identity());

            // Restore the identity.
            let mut public_identity = vec![0; PUBLIC_IDENTITY_CAPACITY];
            let mut public_identity_length = 0;
            let result = unsafe {
                super::ecall_proxy::identity_restore(
                    self.get_id(),
                    &sealed_identity_buf.sealed_data,
                    sealed_identity_length,
                    public_identity.as_mut_ptr(),
                    public_identity.len(),
                    &mut public_identity_length,
                )
            };
            if result != sgx_types::sgx_status_t::SGX_SUCCESS {
                return Err(Error::new(format!("identity_restore: {}", result)));
            }
            public_identity.truncate(public_identity_length);

            // Send the AV report to the enclave.
            let av_report_bytes = saved_identity.get_av_report().write_to_bytes()?;
            let result = unsafe {
                super::ecall_proxy::identity_set_av_report(
                    self.get_id(),
                    av_report_bytes.as_ptr(),
                    av_report_bytes.len(),
                )
            };
            if result != sgx_types::sgx_status_t::SGX_SUCCESS {
                return Err(Error::new(format!("identity_set_av_report: {}", result)));
            }

            // Assemble the enclave identity proof.
            let mut identity_proof = api::IdentityProof::new();
            identity_proof.set_public_identity(public_identity);
            identity_proof.set_av_report(saved_identity.take_av_report());

            Ok(identity_proof)
        } else {
            // TODO: handle other errors

            // Don't have saved identity. Create a new identity.
            let mut saved_identity = api::SavedIdentity::new();

            // Get QE's target info and EPID gid.
            let mut qe_target_info = unsafe { std::mem::zeroed() };
            let mut gid = unsafe { std::mem::zeroed() };
            let result = unsafe { sgx_types::sgx_init_quote(&mut qe_target_info, &mut gid) };
            if result != sgx_types::sgx_status_t::SGX_SUCCESS {
                return Err(Error::new(format!("sgx_init_quote: {}", result)));
            }

            // Retrieve signature revocation list.
            // TODO: implement and enable sigrl
            // let sig_rl: Vec<u8> = ias.sigrl(&gid);

            // Create a new identity.
            let mut sealed_identity_buf: SealedDataBuffer = unsafe { std::mem::zeroed() };
            let mut sealed_identity_length = 0;
            let result = unsafe {
                super::ecall_proxy::identity_create(
                    self.get_id(),
                    &mut sealed_identity_buf.sealed_data,
                    SEALED_DATA_CAPACITY,
                    &mut sealed_identity_length,
                )
            };
            if result != sgx_types::sgx_status_t::SGX_SUCCESS {
                return Err(Error::new(format!("identity_create: {}", result)));
            }

            //
            saved_identity.set_sealed_identity(
                unsafe { &sealed_identity_buf.buffer[..sealed_identity_length] }.to_vec(),
            );

            // Restore the identity.
            let mut public_identity = vec![0; PUBLIC_IDENTITY_CAPACITY];
            let mut public_identity_length = 0;
            let result = unsafe {
                super::ecall_proxy::identity_restore(
                    self.get_id(),
                    &sealed_identity_buf.sealed_data,
                    sealed_identity_length,
                    public_identity.as_mut_ptr(),
                    public_identity.len(),
                    &mut public_identity_length,
                )
            };
            if result != sgx_types::sgx_status_t::SGX_SUCCESS {
                return Err(Error::new(format!("identity_restore: {}", result)));
            }
            public_identity.truncate(public_identity_length);

            // Create a report for QE.
            let mut report = unsafe { std::mem::zeroed() };
            let result = unsafe {
                super::ecall_proxy::identity_create_report(
                    self.get_id(),
                    &qe_target_info,
                    &mut report,
                )
            };
            if result != sgx_types::sgx_status_t::SGX_SUCCESS {
                return Err(Error::new(format!("identity_create_report: {}", result)));
            }

            // Get a quote.
            let mut quote_size = 0;
            let result = unsafe {
                sgx_types::sgx_calc_quote_size(
                    // TODO: implement and enable sigrl
                    std::ptr::null(),
                    0,
                    // sig_rl.as_ptr(),
                    // sig_rl.len() as u32,
                    &mut quote_size,
                )
            };
            if result != sgx_types::sgx_status_t::SGX_SUCCESS {
                return Err(Error::new(format!("sgx_calc_quote_size: {}", result)));
            }
            if quote_size as usize > QUOTE_CAPACITY {
                return Err(Error::new(format!(
                    "Quote identity is too large ({}/{})",
                    quote_size, QUOTE_CAPACITY
                )));
            }
            let mut quote_buf: QuoteBuffer = unsafe { std::mem::zeroed() };
            let nonce = unsafe { std::mem::zeroed() };
            let result = unsafe {
                sgx_types::sgx_get_quote(
                    &report,
                    ias.get_quote_type(),
                    &ias.get_spid(),
                    nonce,
                    // TODO: implement and enable sigrl
                    std::ptr::null(),
                    0,
                    // sig_rl.as_ptr(),
                    // sig_rl.len() as u32,
                    std::ptr::null_mut(),
                    &mut quote_buf.quote,
                    quote_size,
                )
            };
            if result != sgx_types::sgx_status_t::SGX_SUCCESS {
                return Err(Error::new(format!("sgx_get_quote: {}", result)));
            }

            // Verify attestation evidence.
            let av_report = ias.report(unsafe { &quote_buf.buffer[..quote_size as usize] });

            //
            saved_identity.set_av_report(av_report);

            // Send the AV report to the enclave.
            let av_report_bytes = saved_identity
                .get_av_report()
                .write_to_bytes()
                .expect("Message::write_to_bytes");
            let result = unsafe {
                super::ecall_proxy::identity_set_av_report(
                    self.get_id(),
                    av_report_bytes.as_ptr(),
                    av_report_bytes.len(),
                )
            };
            if result != sgx_types::sgx_status_t::SGX_SUCCESS {
                return Err(Error::new(format!("identity_set_av_report: {}", result)));
            }

            // Save the identity.
            if let Some(saved_identity_path) = saved_identity_path {
                let mut file = std::fs::File::create(saved_identity_path)?;
                saved_identity.write_to_writer(&mut file)?;
            }

            // Assemble the enclave identity proof.
            let mut identity_proof = api::IdentityProof::new();
            identity_proof.set_public_identity(public_identity);
            identity_proof.set_av_report(saved_identity.take_av_report());

            Ok(identity_proof)
        }
    }
}
