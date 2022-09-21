//! Intel Attestation Service (IAS) attestation verification report handling.
use std::io::{Cursor, Read, Seek, SeekFrom};

use anyhow::{anyhow, Result};
use base64;
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::prelude::*;
use lazy_static::lazy_static;
use oid_registry::{OID_PKCS1_RSAENCRYPTION, OID_PKCS1_SHA256WITHRSA};
use percent_encoding;
use rsa::{padding::PaddingScheme, pkcs1::DecodeRsaPublicKey, Hash, PublicKey, RsaPublicKey};
use serde_json;
use sgx_isa::{AttributesFlags, Report};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_parser::prelude::*;

use crate::common::{
    sgx::{EnclaveIdentity, MrEnclave, MrSigner, VerifiedQuote},
    time::{insecure_posix_time, update_insecure_posix_time},
};

/// AVR verification error.
#[derive(Error, Debug)]
enum AVRError {
    #[error("failed to parse report body")]
    MalformedReportBody,
    #[error("report body did not contain timestamp")]
    MissingTimestamp,
    #[error("failed to parse timestamp")]
    MalformedTimestamp,
    #[error("timestamp differs by more than 1 day")]
    TimestampOutOfRange,
    #[error("rejecting quote status ({status:?})")]
    QuoteStatusInvalid { status: String },
    #[error("debug enclaves not allowed")]
    DebugEnclave,
    #[error("production enclaves not allowed")]
    ProductionEnclave,
    #[error("AVR did not contain quote status")]
    MissingQuoteStatus,
    #[error("AVR did not contain quote body")]
    MissingQuoteBody,
    #[error("failed to parse quote")]
    MalformedQuote,
    #[error("unable to find exactly 2 certificates")]
    ChainNotTwoCertificates,
    #[error("malformed certificate PEM")]
    MalformedCertificatePEM,
    #[error("malformed certificate DER")]
    MalformedCertificateDER,
    #[error("expired certificate")]
    ExpiredCertificate,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("IAS quotes are disabled by policy")]
    Disabled,
}

pub const QUOTE_CONTEXT_LEN: usize = 8;
/// The purpose of `QuoteContext` is to prevent quotes from being used in
/// different contexts. The value is included as a prefix in report data.
pub type QuoteContext = [u8; QUOTE_CONTEXT_LEN];

// AVR signature validation constants.
const IAS_TRUST_ANCHOR_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV
BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0
YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy
MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL
U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD
DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G
CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e
LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh
rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT
L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe
NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ
byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H
afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf
6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM
RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX
MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50
L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW
BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr
NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq
hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir
IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ
sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi
zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra
Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA
152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB
3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O
DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv
DaVzWh5aiEx+idkSGMnX
-----END CERTIFICATE-----"#;
const PEM_CERTIFICATE_LABEL: &str = "CERTIFICATE";
const IAS_TS_FMT: &str = "%FT%T%.6f";
lazy_static! {
    static ref IAS_TRUST_ANCHOR: Vec<u8> = {
        let pem = match parse_x509_pem(IAS_TRUST_ANCHOR_PEM.as_bytes()) {
            Ok((rem, pem)) => {
                assert!(rem.is_empty(), "anchor PEM has trailing garbage");
                assert!(
                    pem.label == PEM_CERTIFICATE_LABEL,
                    "PEM does not contain a certificate: '{:?}'",
                    pem.label
                );
                pem
            }
            err => panic!("failed to decode anchor PEM: {:?}", err),
        };

        pem.contents.to_vec()
    };
}

/// Quote validity policy.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct QuotePolicy {
    /// Whether IAS quotes are disabled and will always be rejected.
    #[cbor(optional)]
    pub disabled: bool,

    /// Allowed quote statuses.
    ///
    /// Note: QuoteOK and QuoteSwHardeningNeeded are ALWAYS allowed, and do not need to be
    /// specified.
    #[cbor(optional)]
    pub allowed_quote_statuses: Vec<i64>, // TODO: Define ISVEnclaveQuoteStatus type.
}

/// Decoded quote body.
#[derive(Default, Debug)]
struct QuoteBody {
    version: u16,
    signature_type: u16,
    gid: u32,
    isv_svn_qe: u16,
    isv_svn_pce: u16,
    basename: [u8; 32],
    report_body: Report,
}

#[allow(clippy::unused_io_amount)]
impl QuoteBody {
    /// Decode quote body.
    fn decode(quote_body: &[u8]) -> Result<QuoteBody> {
        let mut reader = Cursor::new(quote_body);
        let mut quote_body: QuoteBody = QuoteBody::default();

        // TODO: Should we ensure that reserved bytes are all zero?

        // Quote body.
        quote_body.version = reader.read_u16::<LittleEndian>()?;
        quote_body.signature_type = reader.read_u16::<LittleEndian>()?;
        quote_body.gid = reader.read_u32::<LittleEndian>()?;
        quote_body.isv_svn_qe = reader.read_u16::<LittleEndian>()?;
        quote_body.isv_svn_pce = reader.read_u16::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(4))?; // 4 reserved bytes.
        reader.read_exact(&mut quote_body.basename)?;

        // Report body.
        let mut report_buf = vec![0; Report::UNPADDED_SIZE];
        reader.read(&mut report_buf)?;
        quote_body.report_body = match Report::try_copy_from(&report_buf) {
            Some(r) => r,
            None => return Err(AVRError::MalformedReportBody.into()),
        };

        Ok(quote_body)
    }
}

/// Attestation verification report.
#[derive(Debug, Default, Clone, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct AVR {
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
    pub certificate_chain: Vec<u8>,
}

/// Parsed AVR body.
#[derive(Debug, Clone)]
pub(crate) struct ParsedAVR {
    body: serde_json::Value,
}

impl ParsedAVR {
    pub(crate) fn new(avr: &AVR) -> Result<Self> {
        let body = match serde_json::from_slice(&avr.body) {
            Ok(avr_body) => avr_body,
            _ => return Err(AVRError::MalformedReportBody.into()),
        };
        Ok(Self { body })
    }

    fn isv_enclave_quote_status(&self) -> Result<String> {
        match self.body["isvEnclaveQuoteStatus"].as_str() {
            Some(status) => Ok(status.to_string()),
            None => Err(AVRError::MissingQuoteStatus.into()),
        }
    }

    fn isv_enclave_quote_body(&self) -> Result<String> {
        match self.body["isvEnclaveQuoteBody"].as_str() {
            Some(quote_body) => Ok(quote_body.to_string()),
            None => Err(AVRError::MissingQuoteBody.into()),
        }
    }

    fn timestamp(&self) -> Result<i64> {
        let timestamp = match self.body["timestamp"].as_str() {
            Some(timestamp) => timestamp,
            None => {
                return Err(AVRError::MissingTimestamp.into());
            }
        };
        parse_avr_timestamp(timestamp)
    }
}

/// Verify attestation report.
pub fn verify(avr: &AVR, policy: &QuotePolicy) -> Result<VerifiedQuote> {
    if policy.disabled {
        return Err(AVRError::Disabled.into());
    }

    let unsafe_skip_avr_verification = option_env!("OASIS_UNSAFE_SKIP_AVR_VERIFY").is_some();
    let unsafe_lax_avr_verification = option_env!("OASIS_UNSAFE_LAX_AVR_VERIFY").is_some();

    // Get the time.
    let timestamp_now = insecure_posix_time();

    // Verify IAS signature.
    if !unsafe_skip_avr_verification {
        validate_avr_signature(
            &avr.certificate_chain,
            &avr.body,
            &avr.signature,
            timestamp_now as u64,
        )?;
    }

    // Parse AV report body.
    let avr_body = ParsedAVR::new(avr)?;

    // Check timestamp, reject if report is too old.
    let timestamp = avr_body.timestamp()?;
    if !timestamp_is_fresh(timestamp_now, timestamp) {
        return Err(AVRError::TimestampOutOfRange.into());
    }

    let quote_status = avr_body.isv_enclave_quote_status()?;
    match quote_status.as_str() {
        "OK" | "SW_HARDENING_NEEDED" => {}
        "GROUP_OUT_OF_DATE" | "CONFIGURATION_NEEDED" | "CONFIGURATION_AND_SW_HARDENING_NEEDED" => {
            if !unsafe_lax_avr_verification {
                return Err(AVRError::QuoteStatusInvalid {
                    status: quote_status.to_owned(),
                }
                .into());
            }
        }
        _ => {
            return Err(AVRError::QuoteStatusInvalid {
                status: quote_status.to_owned(),
            }
            .into());
        }
    };

    let quote_body = avr_body.isv_enclave_quote_body()?;
    let quote_body = match base64::decode(&quote_body) {
        Ok(quote_body) => quote_body,
        _ => return Err(AVRError::MalformedQuote.into()),
    };
    let quote_body = match QuoteBody::decode(&quote_body) {
        Ok(quote_body) => quote_body,
        _ => return Err(AVRError::MalformedQuote.into()),
    };

    // Disallow debug enclaves, if we are in production environment and disallow production enclaves,
    // if we are in debug environment.
    let is_debug = quote_body
        .report_body
        .attributes
        .flags
        .contains(AttributesFlags::DEBUG);
    let allow_debug = option_env!("OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES").is_some();
    if is_debug && !allow_debug {
        return Err(AVRError::DebugEnclave.into());
    } else if !is_debug && allow_debug {
        return Err(AVRError::ProductionEnclave.into());
    }

    // Force-ratchet the clock forward, to at least the time in the AVR.
    update_insecure_posix_time(timestamp);

    Ok(VerifiedQuote {
        report_data: quote_body.report_body.reportdata.to_vec(),
        identity: EnclaveIdentity {
            mr_enclave: MrEnclave::from(quote_body.report_body.mrenclave.to_vec()),
            mr_signer: MrSigner::from(quote_body.report_body.mrsigner.to_vec()),
        },
        timestamp,
    })
}

fn parse_avr_timestamp(timestamp: &str) -> Result<i64> {
    let timestamp_unix = match Utc.datetime_from_str(timestamp, IAS_TS_FMT) {
        Ok(timestamp) => timestamp.timestamp(),
        _ => return Err(AVRError::MalformedTimestamp.into()),
    };
    Ok(timestamp_unix)
}

fn validate_avr_signature(
    cert_chain: &[u8],
    message: &[u8],
    signature: &[u8],
    unix_time: u64,
) -> Result<()> {
    // WARNING: This is the entirely wrong way to validate a certificate
    // chain as it does not come close to implementing anything resembling
    // what is specified in RFC 5280 6.1.  There probably should be a CRL
    // check here as well, now that I think about it.
    //
    // The main assumptions made about how exactly the signing key is
    // certified/distributed, and the AVR is signed are based on the
    // following documentation:
    //
    //  * 4.2.2 Report Signature:
    //    * "The Attestation Verification Report is cryptographically
    //       signed by Report Signing Key (owned by the Attestation
    //       Service) using the RSA-SHA256 algorithm."
    //  * 4.2.3 Report Signing Certificate Chain:
    //    * "The public part of Report Key is distributed in the form
    //       of an x.509 digital certificate called Attestation Report
    //       Signing Certificate. It is a leaf certificate issued by
    //       the Attestation Report Signing CA Certificate"
    //    * "A PEM-encoded certificate chain consisting of Attestation
    //       Report Signing Certificate and Attestation Report Signing
    //       CA Certificate is returned..."
    //
    // See: "Attestation Service for Intel(R) Software Guard Extensions
    // (Intel(R) SGX): API Documentation" (Revision: 6.0)

    // Decode the certificate chain from percent encoded PEM to DER.
    let raw_pem = percent_encoding::percent_decode(cert_chain).decode_utf8()?;
    let mut cert_ders = Vec::new();
    for pem in pem::Pem::iter_from_buffer(raw_pem.as_bytes()) {
        let pem = match pem {
            Ok(p) => p,
            Err(_) => return Err(AVRError::MalformedCertificatePEM.into()),
        };
        if pem.label != PEM_CERTIFICATE_LABEL {
            return Err(AVRError::MalformedCertificatePEM.into());
        }
        cert_ders.push(pem.contents);
    }

    // IAS per the API will only ever send two certificates.
    if cert_ders.len() != 2 {
        return Err(AVRError::ChainNotTwoCertificates.into());
    }

    // Convert our timestamp to something that can be used to check
    // certificate expiration.
    let time = ASN1Time::from_timestamp(unix_time as i64)?;

    // Attestation Report Signing CA Certificate:
    //
    // Ensure that it matches the hard-coded copy, and decode it, so
    // that the expiration can be validated and the public key can
    // be used to verify the leaf certificate's signature.
    //
    // This could be more paranoid and check that the cert doesn't
    // have trailing garbage, the usage is correct, etc, but we can
    // take it as a matter of faith that it is well-formed since
    // it is the same as the hard-coded one.
    //
    // TODO/perf: In theory this can be done once and only once, but
    // the borrow checker thwarted my attempts to initialize a tuple
    // containing a X509Certificate and Pem via lazy_static.
    if cert_ders[1] != *IAS_TRUST_ANCHOR {
        return Err(anyhow!("AVR certificate chain trust anchor mismatch"));
    }
    let anchor = match parse_x509_certificate(&cert_ders[1]) {
        Ok((_, cert)) => cert,
        Err(_) => return Err(AVRError::MalformedCertificateDER.into()),
    };
    if !anchor.validity().is_valid_at(time) {
        return Err(AVRError::ExpiredCertificate.into());
    }
    let anchor_pk = extract_certificate_rsa_public_key(&anchor)?;
    if !check_certificate_rsa_signature(&anchor, &anchor_pk) {
        // The hard-coded cert is self-signed.  This will need to be
        // changed if it ever isn't.
        return Err(anyhow!(
            "AVR certificate chain trust anchor has invalid signature"
        ));
    }
    if !anchor.tbs_certificate.is_ca() {
        return Err(anyhow!("AVR certificate trust anchor is not a CA"));
    }

    // Attestation Report Signing Certificate (leaf):
    //
    // Decode the certificate, ensure that it appears to be sensible,
    // and then pull out the public key that presumably signs the AVR.
    let leaf = match parse_x509_certificate(&cert_ders[0]) {
        Ok((rem, cert)) => {
            if !rem.is_empty() {
                return Err(AVRError::MalformedCertificateDER.into());
            }
            cert
        }
        Err(_) => return Err(AVRError::MalformedCertificateDER.into()),
    };
    if !check_certificate_rsa_signature(&leaf, &anchor_pk) {
        return Err(anyhow!("invalid leaf certificate signature"));
    }

    if !leaf.validity().is_valid_at(time) {
        return Err(AVRError::ExpiredCertificate.into());
    }
    match leaf.tbs_certificate.key_usage()? {
        Some(ku) => {
            if !ku.value.digital_signature() {
                return Err(anyhow!("leaf certificate can't sign"));
            }
        }
        None => {
            return Err(anyhow!("leaf cert missing key usage"));
        }
    }

    // Validate the actual signature.
    let leaf_pk = extract_certificate_rsa_public_key(&leaf)?;
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
    let digest = Sha256::new().chain(message).finalize();
    let signature = base64::decode(signature)?;
    leaf_pk
        .verify(padding, &digest, &signature)
        .map_err(|_| AVRError::InvalidSignature)?;
    Ok(())
}

fn extract_certificate_rsa_public_key(cert: &X509Certificate) -> Result<RsaPublicKey> {
    let cert_spki = &cert.tbs_certificate.subject_pki;
    if cert_spki.algorithm.algorithm != OID_PKCS1_RSAENCRYPTION {
        return Err(anyhow!("invalid certificate public key algorithm"));
    }

    match RsaPublicKey::from_pkcs1_der(&cert_spki.subject_public_key.data) {
        Ok(pk) => Ok(pk),
        Err(err) => Err(anyhow!("invalid certificate public key: {:?}", err)),
    }
}

fn check_certificate_rsa_signature(cert: &X509Certificate, public_key: &RsaPublicKey) -> bool {
    if cert.signature_algorithm.algorithm != OID_PKCS1_SHA256WITHRSA {
        return false;
    }
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
    let digest = Sha256::new()
        .chain(cert.tbs_certificate.as_ref())
        .finalize();

    public_key
        .verify(padding, &digest, &cert.signature_value.data)
        .is_ok()
}

/// Return true iff the (POXIX) timestamp is considered "fresh" for the purposes
/// of a cached AVR, given the current time.
pub(crate) fn timestamp_is_fresh(now: i64, timestamp: i64) -> bool {
    (now - timestamp).abs() < 60 * 60 * 24
}

#[cfg(test)]
mod tests {
    use super::*;

    const IAS_CERT_CHAIN: &[u8] =
        include_bytes!("../../../testdata/avr_certificates_urlencoded.pem");

    #[test]
    fn test_validate_avr_signature() {
        const MSG: &[u8] = include_bytes!("../../../testdata/avr_body_group_out_of_date.json");
        const SIG: &[u8] = include_bytes!("../../../testdata/avr_signature_group_out_of_date.sig");
        const SIG_AT: u64 = 1522447346; // 2018-03-30T22:02:26

        // Positive test.
        let result = validate_avr_signature(IAS_CERT_CHAIN, MSG, SIG, SIG_AT);
        assert!(result.is_ok());

        // Invalid timestamp.
        let result = validate_avr_signature(IAS_CERT_CHAIN, MSG, SIG, 0);
        assert!(result.is_err());

        // Bad message.
        let bad_msg: &mut [u8] = &mut MSG.to_owned();
        bad_msg[0] ^= 0x23;
        let result = validate_avr_signature(IAS_CERT_CHAIN, bad_msg, SIG, SIG_AT);
        assert!(result.is_err());

        // Bad signature.
        let bad_sig = base64::decode(SIG).unwrap();
        let bad_sig = &mut bad_sig.to_owned();
        bad_sig[0] ^= 0x42;
        let bad_sig = base64::encode(bad_sig);
        let result = validate_avr_signature(IAS_CERT_CHAIN, MSG, bad_sig.as_bytes(), SIG_AT);
        assert!(result.is_err());

        // Test timestamp validation while we're at it.
        let timestamp = parse_avr_timestamp("2018-03-30T22:02:26.123456").unwrap();
        assert_eq!(timestamp, SIG_AT as i64);
    }
}
