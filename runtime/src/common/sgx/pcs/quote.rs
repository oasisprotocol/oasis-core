use std::{borrow::Cow, ffi::CString, mem};

use byteorder::{ByteOrder, LittleEndian};
use chrono::prelude::*;
use mbedtls::{
    alloc::List as MbedtlsList,
    ecp::{EcGroup, EcPoint},
    hash::{self, Md},
    pk::{EcGroupId, Pk},
    x509::certificate::Certificate,
};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use sgx_isa::{AttributesFlags, Report};

use super::{
    certificates::PCS_TRUST_ROOT,
    constants::*,
    tcb::{QEIdentity, TCBBundle, TCBInfo, TCBLevel, TCBStatus},
    utils::TakePrefix,
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
        let quote = Quote::parse(&self.quote)?;

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
            let sig = quote.signature::<QuoteSignatureEcdsaP256>()?;
            sig.verify(&self.quote, &mut verifier)?;

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

/// An enclave quote.
pub struct Quote<'a> {
    header: QuoteHeader<'a>,
    report_body: Cow<'a, [u8]>,
    signature: Cow<'a, [u8]>,
}

impl<'a> Quote<'a> {
    pub fn parse<T: Into<Cow<'a, [u8]>>>(quote: T) -> Result<Quote<'a>, Error> {
        let mut quote = quote.into();

        // Parse header, depending on version.
        let version = quote
            .take_prefix(mem::size_of::<u16>())
            .map(|v| LittleEndian::read_u16(&v))?;
        let header = match version {
            QUOTE_VERSION_3 => {
                // Version 3.
                let att_key_type = quote
                    .take_prefix(mem::size_of::<u16>())
                    .map(|v| LittleEndian::read_u16(&v))?;
                let attestation_key_type =
                    AttestationKeyType::from_u16(att_key_type).ok_or_else(|| {
                        Error::QuoteParseError(format!(
                            "Unknown attestation key type: {}",
                            att_key_type
                        ))
                    })?;
                let reserved = quote
                    .take_prefix(mem::size_of::<u32>())
                    .map(|v| LittleEndian::read_u32(&v))?;
                if reserved != 0 {
                    return Err(Error::QuoteParseError(format!(
                        "data in reserved field: {:08x}",
                        reserved
                    )));
                }
                let qe_svn = quote
                    .take_prefix(mem::size_of::<u16>())
                    .map(|v| LittleEndian::read_u16(&v))?;
                let pce_svn = quote
                    .take_prefix(mem::size_of::<u16>())
                    .map(|v| LittleEndian::read_u16(&v))?;
                let qe_vendor_id = quote.take_prefix(QE_VENDOR_ID_LEN)?;
                let user_data = quote.take_prefix(QE_USER_DATA_LEN)?;

                // Ensure correct QE vendor and attestation key type.
                if *qe_vendor_id != QE_VENDOR_ID_INTEL[..] {
                    return Err(Error::UnsupportedQEVendor);
                }
                if attestation_key_type != AttestationKeyType::EcdsaP256 {
                    return Err(Error::UnsupportedAttestationKeyType);
                }

                QuoteHeader::V3 {
                    attestation_key_type,
                    qe_svn,
                    pce_svn,
                    qe_vendor_id,
                    user_data,
                }
            }
            _ => {
                return Err(Error::QuoteParseError(format!(
                    "unsupported quote version: {}",
                    version
                )))
            }
        };

        let report_body = quote.take_prefix(REPORT_BODY_LEN)?;

        Ok(Quote {
            header,
            report_body,
            signature: quote,
        })
    }

    pub fn header(&self) -> &QuoteHeader<'a> {
        &self.header
    }

    pub fn report_body(&self) -> &[u8] {
        &self.report_body
    }

    pub fn signature<T: QuoteSignature<'a>>(&self) -> Result<T, Error> {
        match self.header {
            QuoteHeader::V3 {
                attestation_key_type,
                ..
            } => T::parse(attestation_key_type, self.signature.clone()),
        }
    }
}

/// An enclave quote header.
pub enum QuoteHeader<'a> {
    V3 {
        attestation_key_type: AttestationKeyType,
        qe_svn: u16,
        pce_svn: u16,
        qe_vendor_id: Cow<'a, [u8]>,
        user_data: Cow<'a, [u8]>,
    },
}

/// Attestation key type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, FromPrimitive, ToPrimitive)]
#[repr(u16)]
pub enum AttestationKeyType {
    EcdsaP256 = 2,
}

pub trait QuoteSignature<'a>: Sized {
    fn parse(r#type: AttestationKeyType, data: Cow<'a, [u8]>) -> Result<Self, Error>;
}

pub struct QuoteSignatureEcdsaP256<'a> {
    signature: Cow<'a, [u8]>,
    attestation_public_key: Cow<'a, [u8]>,
    qe_report: Cow<'a, [u8]>,
    qe_signature: Cow<'a, [u8]>,
    authentication_data: Cow<'a, [u8]>,
    certification_data_type: CertificationDataType,
    certification_data: Cow<'a, [u8]>,
}

impl<'a> QuoteSignature<'a> for QuoteSignatureEcdsaP256<'a> {
    fn parse(r#type: AttestationKeyType, mut data: Cow<'a, [u8]>) -> Result<Self, Error> {
        if r#type != AttestationKeyType::EcdsaP256 {
            return Err(Error::UnsupportedAttestationKeyType);
        }

        let sig_len = data
            .take_prefix(mem::size_of::<u32>())
            .map(|v| LittleEndian::read_u32(&v))?;
        if sig_len as usize != data.len() {
            return Err(Error::QuoteParseError(
                "invalid signature length".to_string(),
            ));
        }
        let signature = data.take_prefix(ECDSA_P256_SIGNATURE_LEN)?;
        let attestation_public_key = data.take_prefix(ECDSA_P256_PUBLIC_KEY_LEN)?;
        let qe_report = data.take_prefix(REPORT_BODY_LEN)?;
        let qe_signature = data.take_prefix(ECDSA_P256_SIGNATURE_LEN)?;
        let authdata_len = data
            .take_prefix(mem::size_of::<u16>())
            .map(|v| LittleEndian::read_u16(&v))?;
        let authentication_data = data.take_prefix(authdata_len as _)?;
        let cd_type = data
            .take_prefix(mem::size_of::<u16>())
            .map(|v| LittleEndian::read_u16(&v))?;
        let certification_data_type =
            CertificationDataType::from_u16(cd_type).ok_or_else(|| {
                Error::QuoteParseError(format!("unknown certification data type: {}", cd_type))
            })?;
        let certdata_len = data
            .take_prefix(mem::size_of::<u32>())
            .map(|v| LittleEndian::read_u32(&v))?;
        if certdata_len as usize != data.len() {
            return Err(Error::QuoteParseError(
                "invalid certification data length".to_string(),
            ));
        }

        Ok(QuoteSignatureEcdsaP256 {
            signature,
            attestation_public_key,
            qe_report,
            qe_signature,
            authentication_data,
            certification_data_type,
            certification_data: data,
        })
    }
}

impl<'a> QuoteSignatureEcdsaP256<'a> {
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn attestation_public_key(&self) -> &[u8] {
        &self.attestation_public_key
    }

    fn attestation_pk(&self) -> Result<Pk, Error> {
        let mut pt = vec![0x4];
        pt.extend_from_slice(&mut self.attestation_public_key());
        let group = EcGroup::new(EcGroupId::SecP256R1).map_err(|err| Error::Other(err.into()))?;
        let pt = EcPoint::from_binary(&group, &pt).map_err(|err| Error::Other(err.into()))?;
        Pk::public_from_ec_components(group, pt).map_err(|err| Error::Other(err.into()))
    }

    pub fn qe_report(&self) -> &[u8] {
        &self.qe_report
    }

    pub fn qe_signature(&self) -> &[u8] {
        &self.qe_signature
    }

    pub fn authentication_data(&self) -> &[u8] {
        &self.authentication_data
    }

    pub fn certification_data_type(&self) -> CertificationDataType {
        self.certification_data_type
    }

    pub fn certification_data<T: CertificationData<'a>>(&self) -> Result<T, Error> {
        T::parse(
            self.certification_data_type,
            self.certification_data.clone(),
        )
    }

    /// Verify signature against quote using the attestation public key.
    ///
    /// The passed `data` must cover the Quote Header and the Report Data.
    pub fn verify_quote_signature(&'a self, data: &[u8]) -> Result<&'a Self, Error> {
        let sig = get_ecdsa_sig_der(self.signature())?;
        let mut hash = [0u8; 32];
        Md::hash(hash::Type::Sha256, &data, &mut hash).map_err(|err| Error::Other(err.into()))?;

        let mut pk = self.attestation_pk()?;
        pk.verify(mbedtls::hash::Type::Sha256, &hash, &sig)
            .map_err(|_| Error::VerificationFailed("quote signature is invalid".to_string()))?;

        Ok(self)
    }

    /// Verify QE Report signature using the PCK public key.
    pub fn verify_qe_report_signature(&self, pck_pk: &[u8]) -> Result<(), Error> {
        // Verify QE report signature using PCK public key.
        let sig = get_ecdsa_sig_der(self.qe_signature())?;
        let mut hash = [0u8; 32];
        Md::hash(hash::Type::Sha256, &self.qe_report(), &mut hash)
            .map_err(|err| Error::Other(err.into()))?;
        let mut pck_pk = Pk::from_public_key(&pck_pk).map_err(|err| Error::Other(err.into()))?;
        pck_pk
            .verify(mbedtls::hash::Type::Sha256, &hash, &sig)
            .map_err(|_| Error::VerificationFailed("QE report signature is invalid".to_string()))?;

        let mut qe_report = Vec::with_capacity(Report::UNPADDED_SIZE);
        qe_report.extend(self.qe_report());
        qe_report.resize_with(Report::UNPADDED_SIZE, Default::default);
        let qe_report = Report::try_copy_from(&qe_report).ok_or(Error::MalformedQEReport)?;

        // Verify QE report data. First 32 bytes MUST be:
        //   SHA-256(AttestationPublicKey || AuthenticationData)
        // and the remaining 32 bytes MUST be zero.
        let mut hash = [0u8; 32];
        let mut sha256 = Md::new(hash::Type::Sha256).map_err(|err| Error::Other(err.into()))?;
        sha256
            .update(self.attestation_public_key())
            .map_err(|err| Error::Other(err.into()))?;
        sha256
            .update(self.authentication_data())
            .map_err(|err| Error::Other(err.into()))?;
        sha256
            .finish(&mut hash)
            .map_err(|err| Error::Other(err.into()))?;

        if qe_report.reportdata[0..32] != hash {
            return Err(Error::VerificationFailed(
                "QE report data does not match expected value".to_string(),
            ));
        }
        if qe_report.reportdata[32..64] != [0; 32] {
            return Err(Error::VerificationFailed(
                "QE report data does not match expected value".to_string(),
            ));
        }

        Ok(())
    }
}

/// Convert IEEE P1363 ECDSA signature to RFC5480 ASN.1 representation.
fn get_ecdsa_sig_der(sig: &[u8]) -> Result<Vec<u8>, Error> {
    if sig.len() % 2 != 0 {
        return Err(Error::QuoteParseError(
            "malformed ECDSA signature".to_string(),
        ));
    }

    let (r_bytes, s_bytes) = sig.split_at(sig.len() / 2);
    let r = num_bigint::BigUint::from_bytes_be(r_bytes);
    let s = num_bigint::BigUint::from_bytes_be(s_bytes);

    let der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_biguint(&r);
            writer.next().write_biguint(&s);
        })
    });

    Ok(der)
}

pub trait QuoteSignatureEcdsaP256Verifier {
    /// Verify the platform certification data.
    ///
    /// The certification data is in `quote3signature.certification_data()`.
    ///
    /// On success, should return the platform certification public key (PCK) in DER format.
    fn verify_certification_data<'a>(
        &mut self,
        signature: &'a QuoteSignatureEcdsaP256,
    ) -> Result<Vec<u8>, Error>;

    /// Verify the quoting enclave.
    fn verify_qe(&mut self, qe_report: &[u8], authentication_data: &[u8]) -> Result<(), Error>;
}

pub trait QuoteSignatureVerify<'a>: QuoteSignature<'a> {
    type TrustRoot;

    fn verify(&self, quote: &[u8], root_of_trust: Self::TrustRoot) -> Result<(), Error>;
}

impl<'a> QuoteSignatureVerify<'a> for QuoteSignatureEcdsaP256<'a> {
    type TrustRoot = &'a mut dyn QuoteSignatureEcdsaP256Verifier;

    fn verify(&self, quote: &[u8], verifier: Self::TrustRoot) -> Result<(), Error> {
        let pck_pk = verifier.verify_certification_data(self)?;
        self.verify_qe_report_signature(&pck_pk)?;
        verifier.verify_qe(self.qe_report(), self.authentication_data())?;
        self.verify_quote_signature(&quote[..QUOTE_HEADER_LEN + REPORT_BODY_LEN])?;
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, FromPrimitive, ToPrimitive)]
#[repr(u16)]
pub enum CertificationDataType {
    PpidCleartext = 1,
    PpidEncryptedRsa2048 = 2,
    PpidEncryptedRsa3072 = 3,
    PckCertificate = 4,
    PckCertificateChain = 5,
    QeReportCertificationData = 6,
    PlatformManifest = 7,
}

pub trait CertificationData<'a>: Sized {
    fn parse(r#type: CertificationDataType, data: Cow<'a, [u8]>) -> Result<Self, Error>;
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct CertificationDataPpid<'a> {
    pub ppid: Cow<'a, [u8]>,
    pub cpusvn: Cow<'a, [u8]>,
    pub pcesvn: u16,
    pub pceid: u16,
}

impl<'a> CertificationData<'a> for CertificationDataPpid<'a> {
    fn parse(r#type: CertificationDataType, mut data: Cow<'a, [u8]>) -> Result<Self, Error> {
        let ppid_len = match r#type {
            CertificationDataType::PpidEncryptedRsa2048 => 256,
            CertificationDataType::PpidEncryptedRsa3072 => 384,
            _ => return Err(Error::UnexpectedCertificationData),
        };

        let ppid = data.take_prefix(ppid_len)?;
        let cpusvn = data.take_prefix(CPUSVN_LEN)?;
        let pcesvn = data
            .take_prefix(mem::size_of::<u16>())
            .map(|v| LittleEndian::read_u16(&v))?;
        let pceid = data
            .take_prefix(mem::size_of::<u16>())
            .map(|v| LittleEndian::read_u16(&v))?;
        if !data.is_empty() {
            return Err(Error::MalformedCertificationData);
        }

        Ok(CertificationDataPpid {
            ppid,
            cpusvn,
            pcesvn,
            pceid,
        })
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct CertificationDataPckCertificateChain<'a> {
    pub certs: Vec<Cow<'a, str>>,
}

impl<'a> CertificationData<'a> for CertificationDataPckCertificateChain<'a> {
    fn parse(r#type: CertificationDataType, data: Cow<'a, [u8]>) -> Result<Self, Error> {
        if r#type != CertificationDataType::PckCertificateChain {
            return Err(Error::UnexpectedCertificationData);
        }

        let mut data = match data {
            Cow::Borrowed(s) => std::str::from_utf8(s)
                .map(Cow::Borrowed)
                .map_err(|_| Error::MalformedPCK)?,
            Cow::Owned(s) => String::from_utf8(s)
                .map(Cow::Owned)
                .map_err(|_| Error::MalformedPCK)?,
        };

        let mut certs = vec![];
        let mark = "-----END CERTIFICATE-----";
        while let Some(pos) = data.find(mark) {
            certs.push(data.take_prefix(pos + mark.len()).unwrap()); // Pos is always valid.
            if let Some(start) = data.find("-") {
                data.take_prefix(start).unwrap(); // Start is always valid.
            }
        }

        Ok(CertificationDataPckCertificateChain { certs })
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

impl QuoteSignatureEcdsaP256Verifier for QeEcdsaP256Verifier {
    fn verify_certification_data(
        &mut self,
        signature: &QuoteSignatureEcdsaP256,
    ) -> Result<Vec<u8>, Error> {
        // Only PCK certificate chain is supported as certification data.
        let certs = signature
            .certification_data::<CertificationDataPckCertificateChain>()?
            .certs;
        if certs.len() != 3 {
            return Err(Error::UnexpectedCertificateChain);
        }

        // Verify certificate chain.
        let mut cert_chain = MbedtlsList::new();
        for raw_cert in &certs {
            let raw_cert = CString::new(raw_cert.as_ref()).map_err(|_| Error::MalformedPCK)?;
            let cert = Certificate::from_pem(raw_cert.as_bytes_with_nul())
                .map_err(|_| Error::MalformedPCK)?;
            cert_chain.push(cert);
        }
        // TODO: Specify current timestamp.
        Certificate::verify(&cert_chain, &PCS_TRUST_ROOT, None, None).map_err(|_| {
            Error::VerificationFailed("PCK certificate chain is invalid".to_string())
        })?;

        // Extract TCB parameters from the PCK certificate.
        let mut pck_cert = cert_chain.pop_front().unwrap();

        let sgx_extensions = pck_cert
            .extensions()
            .map_err(|_| Error::MalformedPCK)?
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
            return Err(Error::MalformedPCK);
        }

        // Verify TCB level.
        let tcb_level =
            self.tcb_info
                .verify(&fmspc.unwrap(), tcb_comp_svn.unwrap(), pcesvn.unwrap())?;
        self.tcb_level = Some(tcb_level);

        // Extract PCK public key.
        let pck_pk = pck_cert
            .public_key_mut()
            .write_public_der_vec()
            .map_err(|_| Error::MalformedPCK)?;

        Ok(pck_pk)
    }

    fn verify_qe(&mut self, qe_report: &[u8], _authentication_data: &[u8]) -> Result<(), Error> {
        let mut report = Vec::with_capacity(Report::UNPADDED_SIZE);
        report.extend(qe_report);
        report.resize_with(Report::UNPADDED_SIZE, Default::default);

        let report = Report::try_copy_from(&report).ok_or(Error::MalformedQEReport)?;
        self.qe_identity.verify(&report)?;

        Ok(())
    }
}
