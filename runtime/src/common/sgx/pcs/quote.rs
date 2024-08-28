use std::ffi::CString;

use chrono::prelude::*;
use dcap_ql::quote::{self, Quote3SignatureVerify};
use mbedtls::{alloc::List as MbedtlsList, x509::certificate::Certificate};
use sgx_isa::{AttributesFlags, Report};

use super::{
    certificates::PCS_TRUST_ROOT,
    constants::*,
    tcb::{QEIdentity, TCBBundle, TCBInfo, TCBLevel, TCBStatus},
    Error,
};
use crate::common::sgx::{EnclaveIdentity, MrEnclave, MrSigner, VerifiedQuote};

/// Quote validity policy.
#[derive(Clone, Debug, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct QuotePolicy {
    /// Whether PCS quotes are disabled and will always be rejected.
    #[cbor(optional)]
    pub disabled: bool,

    /// Validity (in days) of the TCB collateral.
    pub tcb_validity_period: u16,

    /// Minimum TCB evaluation data number that is considered to be valid. TCB bundles containing
    /// smaller values will be invalid.
    pub min_tcb_evaluation_data_number: u32,

    /// A list of hexadecimal encoded FMSPCs specifying which processor packages and platform
    /// instances are blocked.
    #[cbor(optional)]
    pub fmspc_blacklist: Vec<String>,
}

impl Default for QuotePolicy {
    fn default() -> Self {
        Self {
            disabled: false,
            tcb_validity_period: 30,
            min_tcb_evaluation_data_number: DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER,
            fmspc_blacklist: Vec::new(),
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

        // XXX: We reuse the IAS specific variables to avoid having additional environment
        // variables. Rename these variables when IAS support is removed.
        let unsafe_skip_quote_verification = option_env!("OASIS_UNSAFE_SKIP_AVR_VERIFY").is_some();
        let unsafe_lax_quote_verification = option_env!("OASIS_UNSAFE_LAX_AVR_VERIFY").is_some();

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
        let timestamp = NaiveDateTime::parse_from_str(&tcb_info.issue_date, PCS_TS_FMT)
            .map_err(|err| Error::TCBParseError(err.into()))?
            .and_utc()
            .timestamp();

        // Perform quote verification.
        if !unsafe_skip_quote_verification {
            let mut verifier: QeEcdsaP256Verifier = QeEcdsaP256Verifier::new(tcb_info, qe_identity);
            let sig = quote
                .signature::<quote::Quote3SignatureEcdsaP256>()
                .map_err(|err| Error::QuoteParseError(err.to_string()))?;
            sig.verify(&self.quote, &mut verifier)
                .map_err(|err| Error::VerificationFailed(err.to_string()))?;

            // Validate TCB level.
            match verifier.tcb_level.ok_or(Error::TCBMismatch)?.status {
                TCBStatus::UpToDate | TCBStatus::SWHardeningNeeded => {}
                TCBStatus::OutOfDate
                | TCBStatus::ConfigurationNeeded
                | TCBStatus::OutOfDateConfigurationNeeded
                    if unsafe_lax_quote_verification => {}
                _ => {
                    return Err(Error::TCBOutOfDate);
                }
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

/// Quoting Enclave ECDSA P-256 verifier.
pub struct QeEcdsaP256Verifier {
    tcb_info: TCBInfo,
    qe_identity: QEIdentity,
    tcb_level: Option<TCBLevel>,
}

impl QeEcdsaP256Verifier {
    /// Create a new verifier.
    pub fn new(tcb_info: TCBInfo, qe_identity: QEIdentity) -> Self {
        Self {
            tcb_info,
            qe_identity,
            tcb_level: None,
        }
    }

    /// Get the TCB level.
    /// This will return `None` if the quote has not been verified yet.
    pub fn tcb_level(&self) -> Option<TCBLevel> {
        self.tcb_level.clone()
    }
}

impl quote::Quote3SignatureEcdsaP256Verifier for QeEcdsaP256Verifier {
    fn verify_certification_data(
        &mut self,
        quote3signature: &quote::Quote3SignatureEcdsaP256,
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
        Certificate::verify(&cert_chain, &PCS_TRUST_ROOT, None, None)?;

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
