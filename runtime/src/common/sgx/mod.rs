//! SGX-specific functionality.

pub mod egetkey;
pub mod ias;
pub mod seal;

#[cfg(target_env = "sgx")]
use sgx_isa::Report;

impl_bytes!(MrEnclave, 32, "Enclave hash (MRENCLAVE).");
impl_bytes!(MrSigner, 32, "Enclave signer hash (MRSIGNER).");

/// Enclave identity.
#[derive(Debug, Default, Clone, Hash, Eq, PartialEq, cbor::Encode, cbor::Decode)]
pub struct EnclaveIdentity {
    pub mr_enclave: MrEnclave,
    pub mr_signer: MrSigner,
}

impl EnclaveIdentity {
    pub fn current() -> Option<Self> {
        #[cfg(target_env = "sgx")]
        {
            let report = Report::for_self();
            Some(EnclaveIdentity {
                mr_enclave: MrEnclave(report.mrenclave),
                mr_signer: MrSigner(report.mrsigner),
            })
        }

        // TODO: There should be a mechanism for setting mock values for
        // the purpose of testing.
        #[cfg(not(target_env = "sgx"))]
        None
    }

    pub fn fortanix_test(mr_enclave: MrEnclave) -> Self {
        Self {
            mr_enclave,
            mr_signer: MrSigner::from(
                "9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a",
            ),
        }
    }
}
