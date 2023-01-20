//! Intel Provisioning Certification Services (PCS) quote handling.
use std::ffi::CString;

use byteorder::{ByteOrder, LittleEndian};
use chrono::{prelude::*, Duration};
use dcap_ql::quote::{self, Quote3SignatureVerify};
use mbedtls::{
    alloc::{Box as MbedtlsBox, List as MbedtlsList},
    x509::certificate::Certificate,
};
use rustc_hex::FromHex;
use serde_json::value::RawValue;
use sgx_isa::{AttributesFlags, Report};

use super::{EnclaveIdentity, MrEnclave, MrSigner, VerifiedQuote};

// Required values of various TCB fields.
const REQUIRED_TCB_INFO_VERSION: u32 = 2;
const REQUIRED_QE_ID: &str = "QE";
const REQUIRED_QE_IDENTITY_VERSION: u32 = 2;
const DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER: u32 = 12; // As of 2022-08-01.

// Intel's PCS signing root certificate.
const PCS_TRUST_ROOT_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----"#;
lazy_static::lazy_static! {
    static ref PCS_TRUST_ROOT: MbedtlsList<Certificate> = {
        let mut cert_chain = MbedtlsList::new();
        let raw_cert = CString::new(PCS_TRUST_ROOT_CERT.as_bytes()).unwrap();
        let cert = Certificate::from_pem(raw_cert.as_bytes_with_nul()).unwrap();
        cert_chain.push(cert);

        cert_chain
    };
}
// PCS timestamp format.
const PCS_TS_FMT: &str = "%FT%T%.9fZ";

// OIDs for PCK X509 certificate extensions.
const PCK_SGX_EXTENSIONS_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1];
const PCK_SGX_EXTENSIONS_FMSPC_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 4];
const PCK_SGX_EXTENSIONS_TCB_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 2];

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

/// Quote validity policy.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
pub struct QuotePolicy {
    /// Whether PCS quotes are disabled and will always be rejected.
    #[cbor(optional)]
    pub disabled: bool,

    /// Validity (in days) of the TCB collateral.
    pub tcb_validity_period: u16,

    /// Minimum TCB evaluation data number that is considered to be valid. TCB bundles containing
    /// smaller values will be invalid.
    pub min_tcb_evaluation_data_number: u32,
}

impl Default for QuotePolicy {
    fn default() -> Self {
        Self {
            disabled: false,
            tcb_validity_period: 30,
            min_tcb_evaluation_data_number: DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER,
        }
    }
}

impl QuotePolicy {
    /// Whether the quote with timestamp `ts` is expired.
    pub fn is_expired(&self, now: i64, ts: i64) -> bool {
        if self.disabled {
            return true;
        }

        now.checked_sub(ts)
            .map(|d| d > 60 * 60 * 24 * (self.tcb_validity_period as i64))
            .expect("quote timestamp is in the future") // This should never happen.
    }
}

/// An attestation quote together with the TCB bundle required for its verification.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct QuoteBundle {
    #[cbor(rename = "quote")]
    pub quote: Vec<u8>,

    #[cbor(rename = "tcb")]
    pub tcb: TCBBundle,
}

impl QuoteBundle {
    /// Verify the quote bundle.
    pub fn verify(&self, policy: &QuotePolicy, ts: DateTime<Utc>) -> Result<VerifiedQuote, Error> {
        if policy.disabled {
            return Err(Error::Disabled);
        }

        // Parse the quote.
        let quote = quote::Quote::parse(&self.quote)
            .map_err(|err| Error::QuoteParseError(err.to_string()))?;

        // Ensure correct QE vendor and attestation key type.
        let &quote::QuoteHeader::V3 {
            attestation_key_type,
            ref qe3_vendor_id,
            ..
        } = quote.header();

        if qe3_vendor_id != &&quote::QE3_VENDOR_ID_INTEL[..] {
            return Err(Error::UnsupportedQEVendor);
        }

        if attestation_key_type != quote::Quote3AttestationKeyType::EcdsaP256 {
            return Err(Error::UnsupportedAttestationKeyType);
        }

        // Verify TCB bundle and get TCB info and QE identity.
        let mut tcb_cert = self.tcb.verify_certificates(ts)?;
        let qe_identity = self
            .tcb
            .qe_identity
            .open(ts, policy, tcb_cert.public_key_mut())?;
        let tcb_info = self
            .tcb
            .tcb_info
            .open(ts, policy, tcb_cert.public_key_mut())?;

        // We use the TCB info issue date as the timestamp.
        let timestamp = Utc
            .datetime_from_str(&tcb_info.issue_date, PCS_TS_FMT)
            .map_err(|err| Error::TCBParseError(err.into()))?
            .timestamp();

        // Perform quote verification.
        let mut verifier = Verifier {
            tcb_info,
            qe_identity,
            tcb_level: None,
        };
        let sig = quote
            .signature::<quote::Quote3SignatureEcdsaP256>()
            .map_err(|err| Error::QuoteParseError(err.to_string()))?;
        sig.verify(&self.quote, &mut verifier)
            .map_err(|err| Error::VerificationFailed(err.to_string()))?;

        // Validate TCB level.
        match verifier.tcb_level.ok_or(Error::TCBMismatch)?.status {
            TCBStatus::UpToDate | TCBStatus::SWHardeningNeeded => {}
            _ => {
                return Err(Error::TCBOutOfDate);
            }
        }

        // Parse report body.
        let mut report_body = Vec::with_capacity(Report::UNPADDED_SIZE);
        report_body.extend(quote.report_body());
        report_body.resize_with(Report::UNPADDED_SIZE, Default::default);
        let report_body = Report::try_copy_from(&report_body).ok_or(Error::MalformedReport)?;

        // Disallow debug enclaves, if we are in production environment and disallow production
        // enclaves, if we are in debug environment.
        let is_debug = report_body
            .attributes
            .flags
            .contains(AttributesFlags::DEBUG);
        let allow_debug = option_env!("OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES").is_some();
        if is_debug && !allow_debug {
            return Err(Error::DebugEnclave);
        } else if !is_debug && allow_debug {
            return Err(Error::ProductionEnclave);
        }

        Ok(VerifiedQuote {
            report_data: report_body.reportdata.to_vec(),
            identity: EnclaveIdentity {
                mr_enclave: MrEnclave::from(report_body.mrenclave.to_vec()),
                mr_signer: MrSigner::from(report_body.mrsigner.to_vec()),
            },
            timestamp,
        })
    }
}

struct Verifier {
    tcb_info: TCBInfo,
    qe_identity: QEIdentity,
    tcb_level: Option<TCBLevel>,
}

impl quote::Quote3SignatureEcdsaP256Verifier for Verifier {
    fn verify_certification_data<'a>(
        &mut self,
        quote3signature: &'a quote::Quote3SignatureEcdsaP256,
    ) -> quote::Result<Vec<u8>> {
        // Only PCK certificate chain is supported as certification data.
        let certs = quote3signature
            .certification_data::<quote::Qe3CertDataPckCertChain>()?
            .certs;
        if certs.len() != 3 {
            return Err(Error::UnexpectedCertificateChain.into());
        }

        // Verify certificate chain.
        let mut cert_chain = MbedtlsList::new();
        for raw_cert in &certs {
            let raw_cert = CString::new(raw_cert.as_ref())?;
            let cert = Certificate::from_pem(raw_cert.as_bytes_with_nul())?;
            cert_chain.push(cert);
        }
        // TODO: Specify current timestamp.
        Certificate::verify(&cert_chain, &PCS_TRUST_ROOT, None)?;

        // Extract TCB parameters from the PCK certificate.
        let mut pck_cert = cert_chain.pop_front().unwrap();

        let sgx_extensions = pck_cert
            .extensions()?
            .into_iter()
            .find(|ext| ext.oid.as_ref() == PCK_SGX_EXTENSIONS_OID)
            .ok_or(Error::TCBVerificationFailed)?;
        let mut fmspc: Option<Vec<u8>> = None;
        let mut tcb_comp_svn: Option<[u32; 16]> = None;
        let mut pcesvn: Option<u32> = None;
        yasna::parse_der(&sgx_extensions.value, |reader| {
            reader.read_sequence_of(|reader| {
                reader.read_sequence(|reader| {
                    match reader.next().read_oid()?.as_ref() {
                        PCK_SGX_EXTENSIONS_FMSPC_OID => {
                            // FMSPC
                            let raw_fmspc = reader.next().read_bytes()?;
                            if raw_fmspc.len() != 6 {
                                return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid));
                            }
                            fmspc = Some(raw_fmspc);
                        }
                        PCK_SGX_EXTENSIONS_TCB_OID => {
                            // TCB
                            reader.next().read_sequence_of(|reader| {
                                reader.read_sequence(|reader| {
                                    let comp_id =
                                        *reader.next().read_oid()?.as_ref().last().unwrap();
                                    if (1..=16).contains(&comp_id) {
                                        // TCB Component SVNs
                                        tcb_comp_svn.get_or_insert([0; 16])
                                            [(comp_id - 1) as usize] = reader.next().read_u32()?;
                                    } else if comp_id == 17 {
                                        // PCESVN
                                        pcesvn = Some(reader.next().read_u32()?);
                                    } else if comp_id == 18 {
                                        // CPUSVN
                                        reader.next().read_bytes()?;
                                    }
                                    Ok(())
                                })
                            })?;
                        }
                        _ => {
                            reader.next().read_der()?;
                        }
                    }

                    Ok(())
                })
            })
        })
        .map_err(|_| Error::MalformedPCK)?;
        if fmspc.is_none() || tcb_comp_svn.is_none() || pcesvn.is_none() {
            return Err(Error::MalformedPCK.into());
        }

        // Verify TCB level.
        let tcb_level =
            self.tcb_info
                .verify(&fmspc.unwrap(), tcb_comp_svn.unwrap(), pcesvn.unwrap())?;
        self.tcb_level = Some(tcb_level);

        // Extract PCK public key.
        let pck_pk = pck_cert.public_key_mut().write_public_der_vec()?;

        Ok(pck_pk)
    }

    fn verify_qe3(&mut self, qe3_report: &[u8], _authentication_data: &[u8]) -> quote::Result<()> {
        let mut report = Vec::with_capacity(Report::UNPADDED_SIZE);
        report.extend(qe3_report);
        report.resize_with(Report::UNPADDED_SIZE, Default::default);

        let report = Report::try_copy_from(&report).ok_or(Error::MalformedQEReport)?;
        self.qe_identity.verify(&report)?;

        Ok(())
    }
}

/// The TCB bundle contains all the required components to verify a quote's TCB.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct TCBBundle {
    #[cbor(rename = "tcb_info")]
    pub tcb_info: SignedTCBInfo,

    #[cbor(rename = "qe_id")]
    pub qe_identity: SignedQEIdentity,

    #[cbor(rename = "certs")]
    pub certificates: Vec<u8>,
}

impl TCBBundle {
    fn verify_certificates(&self, _ts: DateTime<Utc>) -> Result<MbedtlsBox<Certificate>, Error> {
        let raw_certs =
            CString::new(&*self.certificates).map_err(|err| Error::TCBParseError(err.into()))?;
        let mut cert_chain = Certificate::from_pem_multiple(raw_certs.as_bytes_with_nul())
            .map_err(|err| Error::TCBParseError(err.into()))?;
        if cert_chain.iter().count() != 2 {
            return Err(Error::UnexpectedCertificateChain);
        }

        // TODO: Specify current timestamp.
        Certificate::verify(&cert_chain, &PCS_TRUST_ROOT, None)
            .map_err(|_| Error::TCBVerificationFailed)?;

        Ok(cert_chain.pop_front().unwrap())
    }
}

#[inline]
fn encode_raw_value(value: &Box<RawValue>) -> Vec<u8> {
    value.get().as_bytes().to_owned()
}

#[inline]
fn decode_raw_value(value: Vec<u8>) -> Result<Box<RawValue>, cbor::DecodeError> {
    RawValue::from_string(String::from_utf8(value).map_err(|_| cbor::DecodeError::UnexpectedType)?)
        .map_err(|_| cbor::DecodeError::UnexpectedType)
}

/// A signed TCB info structure.
#[derive(Clone, Debug, Default, serde::Deserialize, cbor::Encode, cbor::Decode)]
pub struct SignedTCBInfo {
    #[cbor(
        rename = "tcb_info",
        serialize_with = "encode_raw_value",
        deserialize_with = "decode_raw_value"
    )]
    #[serde(rename = "tcbInfo")]
    pub tcb_info: Box<RawValue>,

    #[cbor(rename = "signature")]
    #[serde(rename = "signature")]
    pub signature: String,
}

impl PartialEq for SignedTCBInfo {
    fn eq(&self, other: &SignedTCBInfo) -> bool {
        self.tcb_info.get() == other.tcb_info.get() && self.signature == other.signature
    }
}

impl Eq for SignedTCBInfo {}

fn open_signed_tcb<'a, T: serde::Deserialize<'a>>(
    data: &'a str,
    signature: &str,
    pk: &mut mbedtls::pk::Pk,
) -> Result<T, Error> {
    let mut hash = [0u8; 32];
    mbedtls::hash::Md::hash(mbedtls::hash::Type::Sha256, data.as_bytes(), &mut hash)
        .map_err(|_| Error::TCBVerificationFailed)?;
    let sig: Vec<u8> = signature
        .from_hex()
        .map_err(|_| Error::TCBVerificationFailed)?;

    // Convert IEEE P1363 ECDSA signature to RFC5480 ASN.1 representation.
    if sig.len() % 2 != 0 {
        return Err(Error::TCBVerificationFailed);
    }

    let (r_bytes, s_bytes) = sig.split_at(sig.len() / 2);
    let r = num_bigint::BigUint::from_bytes_be(r_bytes);
    let s = num_bigint::BigUint::from_bytes_be(s_bytes);

    let sig = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_biguint(&r);
            writer.next().write_biguint(&s);
        })
    });

    pk.verify(mbedtls::hash::Type::Sha256, &hash, &sig)
        .map_err(|_| Error::TCBVerificationFailed)?;

    serde_json::from_str(data).map_err(|err| Error::TCBParseError(err.into()))
}

impl SignedTCBInfo {
    fn open(
        &self,
        ts: DateTime<Utc>,
        policy: &QuotePolicy,
        pk: &mut mbedtls::pk::Pk,
    ) -> Result<TCBInfo, Error> {
        let ti: TCBInfo = open_signed_tcb(self.tcb_info.get(), &self.signature, pk)?;
        ti.validate(ts, policy)?;

        Ok(ti)
    }
}

/// TCB info body.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct TCBInfo {
    #[serde(rename = "version")]
    pub version: u32,

    #[serde(rename = "issueDate")]
    pub issue_date: String,

    #[serde(rename = "nextUpdate")]
    pub next_update: String,

    #[serde(rename = "fmspc")]
    pub fmspc: String,

    #[serde(rename = "pceId")]
    pub pceid: String,

    #[serde(rename = "tcbType")]
    pub tcb_type: u32,

    #[serde(rename = "tcbEvaluationDataNumber")]
    pub tcb_evaluation_data_number: u32,

    #[serde(rename = "tcbLevels")]
    pub tcb_levels: Vec<TCBLevel>,
}

impl TCBInfo {
    fn validate(&self, ts: DateTime<Utc>, policy: &QuotePolicy) -> Result<(), Error> {
        if self.version != REQUIRED_TCB_INFO_VERSION {
            return Err(Error::TCBParseError(anyhow::anyhow!(
                "unexpected TCB info version"
            )));
        }

        // Validate TCB info is not expired/not yet valid based on current time.
        let issue_date = Utc
            .datetime_from_str(&self.issue_date, PCS_TS_FMT)
            .map_err(|err| Error::TCBParseError(err.into()))?;
        let _next_update = Utc
            .datetime_from_str(&self.next_update, PCS_TS_FMT)
            .map_err(|err| Error::TCBParseError(err.into()))?;
        if issue_date > ts {
            return Err(Error::TCBExpired);
        }
        if ts - issue_date > Duration::days(policy.tcb_validity_period.into()) {
            return Err(Error::TCBExpired);
        }

        if self.tcb_evaluation_data_number < policy.min_tcb_evaluation_data_number {
            return Err(Error::TCBEvaluationDataNumberInvalid);
        }

        Ok(())
    }

    fn verify(
        &self,
        fmspc: &[u8],
        tcb_comp_svn: [u32; 16],
        pcesvn: u32,
    ) -> Result<TCBLevel, Error> {
        // Validate FMSPC matches.
        let expected_fmspc: Vec<u8> = self
            .fmspc
            .from_hex()
            .map_err(|err| Error::TCBParseError(err.into()))?;
        if fmspc != expected_fmspc {
            return Err(Error::TCBMismatch);
        }

        // Find first matching TCB level.
        let level = self
            .tcb_levels
            .iter()
            .find(|level| level.matches(&tcb_comp_svn, pcesvn))
            .ok_or(Error::TCBOutOfDate)?
            .clone();

        Ok(level)
    }
}

/// A platform TCB level.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct TCBLevel {
    #[serde(rename = "tcb")]
    pub tcb: TCBVersions,

    #[serde(rename = "tcbDate")]
    pub date: String,

    #[serde(rename = "tcbStatus")]
    pub status: TCBStatus,

    #[serde(default, rename = "advisoryIDs")]
    pub advisory_ids: Vec<String>,
}

impl TCBLevel {
    fn matches(&self, tcb_comp_svn: &[u32], pcesvn: u32) -> bool {
        // a) Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate (from 01 to
        //    16) with the corresponding values in the TCB Level. If all SGX TCB Comp SVNs in the
        //    certificate are greater or equal to the corresponding values in TCB Level, go to b,
        //    otherwise move to the next item on TCB Levels list.
        for (i, svn) in [
            self.tcb.comp01svn,
            self.tcb.comp02svn,
            self.tcb.comp03svn,
            self.tcb.comp04svn,
            self.tcb.comp05svn,
            self.tcb.comp06svn,
            self.tcb.comp07svn,
            self.tcb.comp08svn,
            self.tcb.comp09svn,
            self.tcb.comp10svn,
            self.tcb.comp11svn,
            self.tcb.comp12svn,
            self.tcb.comp13svn,
            self.tcb.comp14svn,
            self.tcb.comp15svn,
            self.tcb.comp16svn,
        ]
        .iter()
        .enumerate()
        {
            // At least one SVN is lower, no match.
            if tcb_comp_svn[i] < *svn {
                return false;
            }
        }

        // b) Compare PCESVN value retrieved from the SGX PCK certificate with the corresponding value
        //    in the TCB Level. If it is greater or equal to the value in TCB Level, read status
        //    assigned to this TCB level. Otherwise, move to the next item on TCB Levels list.
        if self.tcb.pcesvn < pcesvn {
            return false;
        }

        // Match.
        true
    }
}

/// TCB versions.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct TCBVersions {
    #[serde(rename = "pcesvn")]
    pub pcesvn: u32,

    #[serde(rename = "sgxtcbcomp01svn")]
    pub comp01svn: u32,
    #[serde(rename = "sgxtcbcomp02svn")]
    pub comp02svn: u32,
    #[serde(rename = "sgxtcbcomp03svn")]
    pub comp03svn: u32,
    #[serde(rename = "sgxtcbcomp04svn")]
    pub comp04svn: u32,
    #[serde(rename = "sgxtcbcomp05svn")]
    pub comp05svn: u32,
    #[serde(rename = "sgxtcbcomp06svn")]
    pub comp06svn: u32,
    #[serde(rename = "sgxtcbcomp07svn")]
    pub comp07svn: u32,
    #[serde(rename = "sgxtcbcomp08svn")]
    pub comp08svn: u32,
    #[serde(rename = "sgxtcbcomp09svn")]
    pub comp09svn: u32,
    #[serde(rename = "sgxtcbcomp10svn")]
    pub comp10svn: u32,
    #[serde(rename = "sgxtcbcomp11svn")]
    pub comp11svn: u32,
    #[serde(rename = "sgxtcbcomp12svn")]
    pub comp12svn: u32,
    #[serde(rename = "sgxtcbcomp13svn")]
    pub comp13svn: u32,
    #[serde(rename = "sgxtcbcomp14svn")]
    pub comp14svn: u32,
    #[serde(rename = "sgxtcbcomp15svn")]
    pub comp15svn: u32,
    #[serde(rename = "sgxtcbcomp16svn")]
    pub comp16svn: u32,
}

/// TCB status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
pub enum TCBStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
    #[serde(other)]
    Invalid,
}

impl Default for TCBStatus {
    fn default() -> Self {
        Self::Invalid
    }
}

/// A signed QE identity structure.
#[derive(Clone, Debug, Default, serde::Deserialize, cbor::Encode, cbor::Decode)]
pub struct SignedQEIdentity {
    #[cbor(
        rename = "enclave_identity",
        serialize_with = "encode_raw_value",
        deserialize_with = "decode_raw_value"
    )]
    #[serde(rename = "enclaveIdentity")]
    pub enclave_identity: Box<RawValue>,

    #[cbor(rename = "signature")]
    #[serde(rename = "signature")]
    pub signature: String,
}

impl PartialEq for SignedQEIdentity {
    fn eq(&self, other: &SignedQEIdentity) -> bool {
        self.enclave_identity.get() == other.enclave_identity.get()
            && self.signature == other.signature
    }
}

impl Eq for SignedQEIdentity {}

impl SignedQEIdentity {
    fn open(
        &self,
        ts: DateTime<Utc>,
        policy: &QuotePolicy,
        pk: &mut mbedtls::pk::Pk,
    ) -> Result<QEIdentity, Error> {
        let qe: QEIdentity = open_signed_tcb(self.enclave_identity.get(), &self.signature, pk)?;
        qe.validate(ts, policy)?;

        Ok(qe)
    }
}

/// QE identity body.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct QEIdentity {
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "version")]
    pub version: u32,

    #[serde(rename = "issueDate")]
    pub issue_date: String,

    #[serde(rename = "nextUpdate")]
    pub next_update: String,

    #[serde(rename = "tcbEvaluationDataNumber")]
    pub tcb_evaluation_data_number: u32,

    #[serde(rename = "miscselect")]
    pub miscselect: String,

    #[serde(rename = "miscselectMask")]
    pub miscselect_mask: String,

    #[serde(rename = "attributes")]
    pub attributes: String,

    #[serde(rename = "attributesMask")]
    pub attributes_mask: String,

    #[serde(rename = "mrsigner")]
    pub mr_signer: String,

    #[serde(rename = "isvprodid")]
    pub isv_prod_id: u16,

    #[serde(rename = "tcbLevels")]
    pub tcb_levels: Vec<EnclaveTCBLevel>,
}

impl QEIdentity {
    fn validate(&self, ts: DateTime<Utc>, policy: &QuotePolicy) -> Result<(), Error> {
        if self.id != REQUIRED_QE_ID {
            return Err(Error::TCBParseError(anyhow::anyhow!("unexpected QE ID")));
        }
        if self.version != REQUIRED_QE_IDENTITY_VERSION {
            return Err(Error::TCBParseError(anyhow::anyhow!(
                "unexpected QE identity version"
            )));
        }

        // Validate QE identity is not expired/not yet valid based on current time.
        let issue_date = Utc
            .datetime_from_str(&self.issue_date, PCS_TS_FMT)
            .map_err(|err| Error::TCBParseError(err.into()))?;
        let _next_update = Utc
            .datetime_from_str(&self.next_update, PCS_TS_FMT)
            .map_err(|err| Error::TCBParseError(err.into()))?;
        if issue_date > ts {
            return Err(Error::TCBExpired);
        }
        if ts - issue_date > Duration::days(policy.tcb_validity_period.into()) {
            return Err(Error::TCBExpired);
        }

        if self.tcb_evaluation_data_number < policy.min_tcb_evaluation_data_number {
            return Err(Error::TCBEvaluationDataNumberInvalid);
        }

        Ok(())
    }

    fn verify(&self, report: &Report) -> Result<(), Error> {
        // Verify if MRSIGNER field retrieved from SGX Enclave Report is equal to the value of
        // mrsigner field in QE Identity.
        let expected_mr_signer: Vec<u8> = self
            .mr_signer
            .from_hex()
            .map_err(|_| Error::TCBParseError(anyhow::anyhow!("malformed QE MRSIGNER")))?;
        if expected_mr_signer != report.mrsigner {
            return Err(Error::TCBVerificationFailed);
        }

        // Verify if ISVPRODID field retrieved from SGX Enclave Report is equal to the value of
        // isvprodid field in QE Identity.
        if self.isv_prod_id != report.isvprodid {
            return Err(Error::TCBVerificationFailed);
        }

        // Apply miscselectMask (binary mask) from QE Identity to MISCSELECT field retrieved from
        // SGX Enclave Report. Verify if the outcome (miscselectMask & MISCSELECT) is equal to the
        // value of miscselect field in QE Identity.
        let raw_miscselect: Vec<u8> = self
            .miscselect
            .from_hex()
            .map_err(|_| Error::TCBParseError(anyhow::anyhow!("malformed QE miscselect")))?;
        if raw_miscselect.len() != 4 {
            return Err(Error::TCBParseError(anyhow::anyhow!(
                "malformed QE miscselect"
            )));
        }
        let raw_miscselect_mask: Vec<u8> = self
            .miscselect_mask
            .from_hex()
            .map_err(|_| Error::TCBParseError(anyhow::anyhow!("malformed QE miscselect mask")))?;
        if raw_miscselect_mask.len() != 4 {
            return Err(Error::TCBParseError(anyhow::anyhow!(
                "malformed QE miscselect"
            )));
        }
        let expected_miscselect = LittleEndian::read_u32(&raw_miscselect);
        let miscselect_mask = LittleEndian::read_u32(&raw_miscselect_mask);
        if report.miscselect.bits() & miscselect_mask != expected_miscselect {
            return Err(Error::TCBVerificationFailed);
        }

        // Apply attributesMask (binary mask) from QE Identity to ATTRIBUTES field retrieved from
        // SGX Enclave Report. Verify if the outcome (attributesMask & ATTRIBUTES) is equal to the
        // value of attributes field in QE Identity.
        let raw_attributes: Vec<u8> = self
            .attributes
            .from_hex()
            .map_err(|_| Error::TCBParseError(anyhow::anyhow!("malformed QE attributes")))?;
        if raw_attributes.len() != 16 {
            return Err(Error::TCBParseError(anyhow::anyhow!(
                "malformed QE attributes"
            )));
        }
        let raw_attributes_mask: Vec<u8> = self
            .attributes_mask
            .from_hex()
            .map_err(|_| Error::TCBParseError(anyhow::anyhow!("malformed QE attributes mask")))?;
        if raw_attributes_mask.len() != 16 {
            return Err(Error::TCBParseError(anyhow::anyhow!(
                "malformed QE attributes"
            )));
        }
        let expected_flags = LittleEndian::read_u64(&raw_attributes[..8]);
        let expected_xfrm = LittleEndian::read_u64(&raw_attributes[8..]);
        let flags_mask = LittleEndian::read_u64(&raw_attributes_mask[..8]);
        let xfrm_mask = LittleEndian::read_u64(&raw_attributes_mask[8..]);
        if report.attributes.flags.bits() & flags_mask != expected_flags {
            return Err(Error::TCBVerificationFailed);
        }
        if report.attributes.xfrm & xfrm_mask != expected_xfrm {
            return Err(Error::TCBVerificationFailed);
        }

        // Determine a TCB status of the Quoting Enclave.
        //
        // Go over the list of TCB Levels (descending order) and find the one that has ISVSVN that
        // is lower or equal to the ISVSVN value from SGX Enclave Report.
        if let Some(level) = self
            .tcb_levels
            .iter()
            .find(|level| level.tcb.isv_svn <= report.isvsvn)
        {
            // Ensure that the TCB is up to date.
            if level.status == TCBStatus::UpToDate {
                return Ok(());
            }
        }

        Err(Error::TCBOutOfDate)
    }
}

/// An enclave TCB level.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct EnclaveTCBLevel {
    #[serde(rename = "tcb")]
    pub tcb: EnclaveTCBVersions,

    #[serde(rename = "tcbDate")]
    pub date: String,

    #[serde(rename = "tcbStatus")]
    pub status: TCBStatus,

    #[serde(default, rename = "advisoryIDs")]
    pub advisory_ids: Vec<String>,
}

/// Enclave TCB versions.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct EnclaveTCBVersions {
    #[serde(rename = "isvsvn")]
    pub isv_svn: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quote_ecdsa_p256_pck_certificatechain() {
        const RAW_QUOTE: &[u8] =
            include_bytes!("../../../testdata/quotev3_ecdsa_p256_pck_chain.bin");
        const RAW_TCB_INFO: &[u8] = include_bytes!("../../../testdata/tcb_fmspc_00606A000000.json"); // From PCS response.
        const RAW_CERTS: &[u8] =
            include_bytes!("../../../testdata/tcb_fmspc_00606A000000_certs.pem"); // From SGX-TCB-Info-Issuer-Chain header.
        const RAW_QE_IDENTITY: &[u8] = include_bytes!("../../../testdata/qe_identity.json"); // From PCS response.

        let qb = QuoteBundle {
            quote: RAW_QUOTE.to_owned(),
            tcb: TCBBundle {
                tcb_info: serde_json::from_slice(RAW_TCB_INFO).unwrap(),
                qe_identity: serde_json::from_slice(RAW_QE_IDENTITY).unwrap(),
                certificates: RAW_CERTS.to_owned(),
            },
        };

        let now = Utc.timestamp_opt(1652701082, 0).unwrap();

        let verified_quote = qb.verify(&QuotePolicy::default(), now).unwrap();
        assert_eq!(
            verified_quote.identity.mr_signer,
            "4025dab7ebda1fbecc4e3637606e021214d0f41c6d0422fd378b2a8b88818459".into()
        );
        assert_eq!(
            verified_quote.identity.mr_enclave,
            "9479d8eddfd7b1b700319419551dc340f688c2ef519a5e18657ecf32981dbd9e".into()
        );
    }

    #[test]
    fn test_quote_bundle_decoding() {
        // From Go implementation.
        const RAW_QUOTE_BUNDLE: &[u8] = include_bytes!("../../../testdata/pcs_quote_bundle.cbor");

        let qb: QuoteBundle = cbor::from_slice(RAW_QUOTE_BUNDLE).unwrap();

        let now = Utc.timestamp_opt(1652701082, 0).unwrap();

        let verified_quote = qb.verify(&QuotePolicy::default(), now).unwrap();
        assert_eq!(
            verified_quote.identity.mr_signer,
            "4025dab7ebda1fbecc4e3637606e021214d0f41c6d0422fd378b2a8b88818459".into()
        );
        assert_eq!(
            verified_quote.identity.mr_enclave,
            "9479d8eddfd7b1b700319419551dc340f688c2ef519a5e18657ecf32981dbd9e".into()
        );
    }
}
