use sgx_types;

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::error::Result;

use super::enclave::Enclave;

pub trait EnclaveCapabilityTEE {
    /// Get the platform's EPID group ID. Used for retrieving the signature revocation list.
    fn capabilitytee_gid(&self) -> Result<sgx_types::sgx_epid_group_id_t>;
    /// Initialize the enclave with a new RAK and get the public key and quote.
    fn capabilitytee_rak_quote(
        &self,
        quote_type: sgx_types::sgx_quote_sign_type_t,
        spid: &sgx_types::sgx_spid_t,
        sig_rl: &[u8],
    ) -> Result<(B256, Vec<u8>)>;
}

impl EnclaveCapabilityTEE for Enclave {
    fn capabilitytee_gid(&self) -> Result<sgx_types::sgx_epid_group_id_t> {
        let mut qe_target_info = unsafe { std::mem::zeroed() };
        let mut gid = unsafe { std::mem::zeroed() };
        let result = unsafe { sgx_types::sgx_init_quote(&mut qe_target_info, &mut gid) };
        if result != sgx_types::sgx_status_t::SGX_SUCCESS {
            return Err(Error::new(format!("sgx_init_quote: {}", result)));
        }
        Ok(gid)
    }

    fn capabilitytee_rak_quote(
        &self,
        quote_type: sgx_types::sgx_quote_sign_type_t,
        spid: &sgx_types::sgx_spid_t,
        sig_rl: &[u8],
    ) -> Result<(B256, Vec<u8>)> {
        // Get QE's target info.
        let mut qe_target_info = unsafe { std::mem::zeroed() };
        let mut gid = unsafe { std::mem::zeroed() };
        let result = unsafe { sgx_types::sgx_init_quote(&mut qe_target_info, &mut gid) };
        if result != sgx_types::sgx_status_t::SGX_SUCCESS {
            return Err(Error::new(format!("sgx_init_quote: {}", result)));
        }

        // Generate RAK and report.
        let mut rak_pub = unsafe { std::mem::zeroed() };
        let mut report = unsafe { std::mem::zeroed() };
        let result = unsafe {
            super::ecall_proxy::capabilitytee_init(
                self.get_id(),
                &mut rak_pub,
                &qe_target_info,
                &mut report,
            )
        };
        if result != sgx_types::sgx_status_t::SGX_SUCCESS {
            return Err(Error::new(format!("capabilitytee_init: {}", result)));
        }

        // Get a quote.
        let mut quote_size = 0;
        let result = unsafe {
            sgx_types::sgx_calc_quote_size(sig_rl.as_ptr(), sig_rl.len() as u32, &mut quote_size)
        };
        if result != sgx_types::sgx_status_t::SGX_SUCCESS {
            return Err(Error::new(format!("sgx_calc_quote_size: {}", result)));
        }
        if quote_size as usize > super::identity::QUOTE_CAPACITY {
            return Err(Error::new(format!(
                "Quote size is too large ({}/{})",
                quote_size,
                super::identity::QUOTE_CAPACITY
            )));
        }
        let mut quote_buf: super::identity::QuoteBuffer = unsafe { std::mem::zeroed() };
        let nonce = unsafe { std::mem::zeroed() };
        let result = unsafe {
            sgx_types::sgx_get_quote(
                &report,
                quote_type,
                spid,
                nonce,
                sig_rl.as_ptr(),
                sig_rl.len() as u32,
                std::ptr::null_mut(),
                &mut quote_buf.quote,
                quote_size,
            )
        };
        if result != sgx_types::sgx_status_t::SGX_SUCCESS {
            return Err(Error::new(format!("sgx_get_quote: {}", result)));
        }

        Ok((
            rak_pub.into(),
            unsafe { quote_buf.buffer }[..quote_size as usize].to_owned(),
        ))
    }
}
