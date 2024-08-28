//! Intel Provisioning Certification Services (PCS) quote handling.

mod certificates;
mod constants;
mod quote;
mod tcb;

/// Possible errors returned by this module.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported QE vendor")]
    UnsupportedQEVendor,
    #[error("unsupported attestation key type")]
    UnsupportedAttestationKeyType,
    #[error("failed to parse quote: {0}")]
    QuoteParseError(String),
    #[error("failed to verify quote: {0}")]
    VerificationFailed(String),
    #[error("unexpected certificate chain")]
    UnexpectedCertificateChain,
    #[error("PCK is malformed")]
    MalformedPCK,
    #[error("failed to parse TCB bundle: {0}")]
    TCBParseError(anyhow::Error),
    #[error("TCB verification failed")]
    TCBVerificationFailed,
    #[error("TCB is expired or not yet valid")]
    TCBExpired,
    #[error("TCB is out of date")]
    TCBOutOfDate,
    #[error("TCB does not match the quote")]
    TCBMismatch,
    #[error("TCB evaluation data number is invalid")]
    TCBEvaluationDataNumberInvalid,
    #[error("FMSPC is blacklisted")]
    BlacklistedFMSPC,
    #[error("QE report is malformed")]
    MalformedQEReport,
    #[error("report is malformed")]
    MalformedReport,
    #[error("debug enclaves not allowed")]
    DebugEnclave,
    #[error("production enclaves not allowed")]
    ProductionEnclave,
    #[error("PCS quotes are disabled by policy")]
    Disabled,
}

pub use quote::{QuoteBundle, QuotePolicy};
pub use tcb::TCBBundle;

#[cfg(test)]
mod tests {
    use chrono::prelude::*;

    use super::*;

    #[test]
    fn test_quote_ecdsa_p256_pck_certificatechain() {
        const RAW_QUOTE: &[u8] =
            include_bytes!("../../../../testdata/quote_v3_ecdsa_p256_pck_chain.bin");
        const RAW_TCB_INFO: &[u8] =
            include_bytes!("../../../../testdata/tcb_info_v3_fmspc_00606A000000.json"); // From PCS V4 response.
        const RAW_CERTS: &[u8] =
            include_bytes!("../../../../testdata/tcb_info_v3_fmspc_00606A000000_certs.pem"); // From PCS V4 response (TCB-Info-Issuer-Chain header).
        const RAW_QE_IDENTITY: &[u8] = include_bytes!("../../../../testdata/qe_identity_v2.json"); // From PCS V4 response.

        let qb = QuoteBundle {
            quote: RAW_QUOTE.to_owned(),
            tcb: TCBBundle {
                tcb_info: serde_json::from_slice(RAW_TCB_INFO).unwrap(),
                qe_identity: serde_json::from_slice(RAW_QE_IDENTITY).unwrap(),
                certificates: RAW_CERTS.to_owned(),
            },
        };

        let now = Utc.timestamp_opt(1671497404, 0).unwrap();

        let verified_quote = qb.verify(&QuotePolicy::default(), now).unwrap();
        assert_eq!(
            verified_quote.identity.mr_signer,
            "9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a".into()
        );
        assert_eq!(
            verified_quote.identity.mr_enclave,
            "68823bc62f409ee33a32ea270cfe45d4b19a6fb3c8570d7bc186cbe062398e8f".into()
        );
    }

    #[test]
    fn test_quote_bundle_decoding() {
        // From Go implementation.
        const RAW_QUOTE_BUNDLE: &[u8] =
            include_bytes!("../../../../testdata/pcs_quote_bundle.cbor");

        let qb: QuoteBundle = cbor::from_slice(RAW_QUOTE_BUNDLE).unwrap();

        let now = Utc.timestamp_opt(1671497404, 0).unwrap();

        let verified_quote = qb.verify(&QuotePolicy::default(), now).unwrap();
        assert_eq!(
            verified_quote.identity.mr_signer,
            "9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a".into()
        );
        assert_eq!(
            verified_quote.identity.mr_enclave,
            "68823bc62f409ee33a32ea270cfe45d4b19a6fb3c8570d7bc186cbe062398e8f".into()
        );
    }

    #[test]
    fn test_quote_blacklisted_fmscp() {
        // From Go implementation.
        const RAW_QUOTE_BUNDLE: &[u8] =
            include_bytes!("../../../../testdata/pcs_quote_bundle.cbor");

        let qb: QuoteBundle = cbor::from_slice(RAW_QUOTE_BUNDLE).unwrap();

        let now = Utc.timestamp_opt(1671497404, 0).unwrap();
        let policy = &QuotePolicy {
            fmspc_blacklist: vec!["00606A000000".to_string()],
            ..Default::default()
        };

        qb.verify(policy, now)
            .expect_err("quote verification should fail for blacklisted FMSPCs");
    }
}
