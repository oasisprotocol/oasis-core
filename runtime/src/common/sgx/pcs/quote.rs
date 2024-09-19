use std::{borrow::Cow, convert::TryInto, ffi::CString, mem};

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
use sgx_isa::AttributesFlags;

use super::{
    certificates::PCS_TRUST_ROOT,
    constants::*,
    policy::QuotePolicy,
    report::{SgxReport, TdAttributes, TdReport},
    tcb::{QEIdentity, TCBBundle, TCBInfo, TCBLevel, TCBStatus},
    utils::TakePrefix,
    Error,
};
use crate::common::sgx::{EnclaveIdentity, MrEnclave, MrSigner, VerifiedQuote};

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
        let tee_type = quote.header().tee_type();

        // Ensure given TEE type is allowed by the policy.
        match (tee_type, &policy.tdx) {
            (TeeType::SGX, _) => { /* Ok. */ }
            (TeeType::TDX, &None) => return Err(Error::TeeTypeNotAllowed),
            (TeeType::TDX, &Some(_)) => { /* Ok. */ }
        }

        // Ensure correct QE vendor.
        if quote.header().qe_vendor_id() != QE_VENDOR_ID_INTEL {
            return Err(Error::UnsupportedQEVendor);
        }

        // Verify TCB bundle and get TCB info and QE identity.
        let mut tcb_cert = self.tcb.verify_certificates(ts)?;
        let qe_identity =
            self.tcb
                .qe_identity
                .open(tee_type, ts, policy, tcb_cert.public_key_mut())?;
        let tcb_info = self
            .tcb
            .tcb_info
            .open(tee_type, ts, policy, tcb_cert.public_key_mut())?;

        // We use the TCB info issue date as the timestamp.
        let timestamp = NaiveDateTime::parse_from_str(&tcb_info.issue_date, PCS_TS_FMT)
            .map_err(|err| Error::TCBParseError(err.into()))?
            .and_utc()
            .timestamp();

        // Perform quote verification.
        if !unsafe_skip_quote_verification {
            let tcb_level = quote.verify(tcb_info, qe_identity)?;

            // Validate TCB level.
            match tcb_level.status {
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

        // Disallow debug enclaves, if we are in production environment and disallow production
        // enclaves, if we are in debug environment.
        let is_debug = quote.report_body().is_debug();
        let allow_debug = option_env!("OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES").is_some();
        if is_debug && !allow_debug {
            return Err(Error::DebugEnclave);
        } else if !is_debug && allow_debug {
            return Err(Error::ProductionEnclave);
        }

        // Verify report against TDX policy.
        if let ReportBody::Tdx(report) = quote.report_body() {
            let tdx_policy = policy.tdx.as_ref().ok_or(Error::TeeTypeNotAllowed)?;
            tdx_policy.verify(report)?;
        }

        Ok(VerifiedQuote {
            report_data: quote.report_body().report_data(),
            identity: quote.report_body().as_enclave_identity(),
            timestamp,
        })
    }
}

/// An enclave quote.
#[derive(Debug)]
pub struct Quote<'a> {
    header: Header<'a>,
    report_body: ReportBody,
    signature: QuoteSignatureEcdsaP256<'a>,
    signed_data: Cow<'a, [u8]>,
}

impl<'a> Quote<'a> {
    pub fn parse<T: Into<Cow<'a, [u8]>>>(quote: T) -> Result<Quote<'a>, Error> {
        let mut quote = quote.into();
        let mut raw = quote.clone();

        // Parse header, depending on version.
        let version = quote
            .take_prefix(mem::size_of::<u16>())
            .map(|v| LittleEndian::read_u16(&v))?;
        match version {
            QUOTE_VERSION_3 => {
                // Version 3 (SGX-ECDSA).
                let att_key_type = quote
                    .take_prefix(mem::size_of::<u16>())
                    .map(|v| LittleEndian::read_u16(&v))?;
                let attestation_key_type = AttestationKeyType::from_u16(att_key_type)
                    .ok_or(Error::UnsupportedAttestationKeyType)?;
                let reserved = quote
                    .take_prefix(mem::size_of::<u32>())
                    .map(|v| LittleEndian::read_u32(&v))?;
                if reserved != 0 {
                    return Err(Error::QuoteParseError("data in reserved field".to_string()));
                }

                let qe_svn = quote
                    .take_prefix(mem::size_of::<u16>())
                    .map(|v| LittleEndian::read_u16(&v))?;
                let pce_svn = quote
                    .take_prefix(mem::size_of::<u16>())
                    .map(|v| LittleEndian::read_u16(&v))?;
                let qe_vendor_id = quote.take_prefix(QE_VENDOR_ID_LEN)?;
                let user_data = quote.take_prefix(QE_USER_DATA_LEN)?;
                let report_body = quote.take_prefix(SGX_REPORT_BODY_LEN)?;
                let report_body = ReportBody::parse(TeeType::SGX, &report_body)?;

                if attestation_key_type != AttestationKeyType::EcdsaP256 {
                    return Err(Error::UnsupportedAttestationKeyType);
                }
                let signature = QuoteSignatureEcdsaP256::parse(version, quote)?;
                let signed_data = raw.take_prefix(QUOTE_HEADER_LEN + SGX_REPORT_BODY_LEN)?;

                Ok(Quote {
                    header: Header::V3 {
                        attestation_key_type,
                        qe_svn,
                        pce_svn,
                        qe_vendor_id,
                        user_data,
                    },
                    report_body,
                    signature,
                    signed_data,
                })
            }
            QUOTE_VERSION_4 => {
                // Version 4 (TDX-ECDSA, SGX-ECDSA).
                let att_key_type = quote
                    .take_prefix(mem::size_of::<u16>())
                    .map(|v| LittleEndian::read_u16(&v))?;
                let attestation_key_type = AttestationKeyType::from_u16(att_key_type)
                    .ok_or(Error::UnsupportedAttestationKeyType)?;

                let tee_type_raw = quote
                    .take_prefix(mem::size_of::<u32>())
                    .map(|v| LittleEndian::read_u32(&v))?;
                let tee_type = TeeType::from_u32(tee_type_raw).ok_or(Error::UnsupportedTeeType)?;

                let reserved1 = quote
                    .take_prefix(mem::size_of::<u16>())
                    .map(|v| LittleEndian::read_u16(&v))?;
                let reserved2 = quote
                    .take_prefix(mem::size_of::<u16>())
                    .map(|v| LittleEndian::read_u16(&v))?;

                if reserved1 != 0 || reserved2 != 0 {
                    return Err(Error::QuoteParseError("data in reserved field".to_string()));
                }

                let qe_vendor_id = quote.take_prefix(QE_VENDOR_ID_LEN)?;
                let user_data = quote.take_prefix(QE_USER_DATA_LEN)?;

                let header = Header::V4 {
                    attestation_key_type,
                    tee_type,
                    qe_vendor_id,
                    user_data,
                };
                let report_body = quote.take_prefix(header.report_body_len())?;
                let report_body = ReportBody::parse(tee_type, &report_body)?;

                if attestation_key_type != AttestationKeyType::EcdsaP256 {
                    return Err(Error::UnsupportedAttestationKeyType);
                }
                let signature = QuoteSignatureEcdsaP256::parse(version, quote)?;
                let signed_data = raw.take_prefix(QUOTE_HEADER_LEN + header.report_body_len())?;

                Ok(Quote {
                    header,
                    report_body,
                    signature,
                    signed_data,
                })
            }
            _ => Err(Error::QuoteParseError(format!(
                "unsupported quote version: {}",
                version
            ))),
        }
    }

    /// Quote header.
    pub fn header(&self) -> &Header<'a> {
        &self.header
    }

    /// Report body.
    pub fn report_body(&self) -> &ReportBody {
        &self.report_body
    }

    /// Verify quote.
    pub fn verify(&self, tcb_info: TCBInfo, qe_identity: QEIdentity) -> Result<TCBLevel, Error> {
        let tdx_comp_svn = self.report_body.tdx_comp_svn();

        let mut verifier: QeEcdsaP256Verifier =
            QeEcdsaP256Verifier::new(tcb_info, qe_identity, tdx_comp_svn);
        self.signature.verify(&self.signed_data, &mut verifier)?;

        Ok(verifier.tcb_level().unwrap())
    }
}

/// An enclave quote header.
#[derive(Debug)]
pub enum Header<'a> {
    V3 {
        attestation_key_type: AttestationKeyType,
        qe_svn: u16,
        pce_svn: u16,
        qe_vendor_id: Cow<'a, [u8]>,
        user_data: Cow<'a, [u8]>,
    },

    V4 {
        attestation_key_type: AttestationKeyType,
        tee_type: TeeType,
        qe_vendor_id: Cow<'a, [u8]>,
        user_data: Cow<'a, [u8]>,
    },
}

impl<'a> Header<'a> {
    /// Quote header version.
    pub fn version(&self) -> u16 {
        match self {
            Self::V3 { .. } => QUOTE_VERSION_3,
            Self::V4 { .. } => QUOTE_VERSION_4,
        }
    }

    /// Attestation key type.
    pub fn attestation_key_type(&self) -> AttestationKeyType {
        match self {
            Self::V3 {
                attestation_key_type,
                ..
            } => *attestation_key_type,
            Self::V4 {
                attestation_key_type,
                ..
            } => *attestation_key_type,
        }
    }

    /// TEE type the quote is for.
    pub fn tee_type(&self) -> TeeType {
        match self {
            Self::V3 { .. } => TeeType::SGX,
            Self::V4 { tee_type, .. } => *tee_type,
        }
    }

    /// Quoting Enclave (QE) vendor identifier.
    pub fn qe_vendor_id(&self) -> &[u8] {
        match self {
            Self::V3 { qe_vendor_id, .. } => qe_vendor_id,
            Self::V4 { qe_vendor_id, .. } => qe_vendor_id,
        }
    }

    /// Length of the report body field.
    pub fn report_body_len(&self) -> usize {
        match self.tee_type() {
            TeeType::SGX => SGX_REPORT_BODY_LEN,
            TeeType::TDX => TDX_REPORT_BODY_LEN,
        }
    }
}

/// TEE type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum TeeType {
    SGX = 0x00000000,
    TDX = 0x00000081,
}

/// Attestation key type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, FromPrimitive, ToPrimitive)]
#[repr(u16)]
pub enum AttestationKeyType {
    EcdsaP256 = 2,
}

/// Report body.
#[derive(Debug)]
pub enum ReportBody {
    Sgx(SgxReport),
    Tdx(TdReport),
}

impl ReportBody {
    /// Parse the report body.
    pub fn parse(tee_type: TeeType, raw: &[u8]) -> Result<Self, Error> {
        match tee_type {
            TeeType::SGX => {
                // Parse SGX report body.
                let mut report_body = Vec::with_capacity(SgxReport::UNPADDED_SIZE);
                report_body.extend(raw);
                report_body.resize_with(SgxReport::UNPADDED_SIZE, Default::default);
                let report =
                    SgxReport::try_copy_from(&report_body).ok_or(Error::MalformedReport)?;

                Ok(Self::Sgx(report))
            }
            TeeType::TDX => {
                // Parse TDX TD report body.
                let report = TdReport::parse(raw)?;

                Ok(Self::Tdx(report))
            }
        }
    }

    /// TDX TEE Component SVNs.
    ///
    /// Returns `None` in case of a non-TDX report body.
    pub fn tdx_comp_svn(&self) -> Option<[u32; 16]> {
        match self {
            Self::Sgx(_) => None,
            Self::Tdx(report) => Some(
                report
                    .tee_tcb_svn
                    .iter()
                    .map(|x| *x as u32)
                    .collect::<Vec<u32>>()
                    .try_into()
                    .unwrap(),
            ),
        }
    }

    /// Whether the report indicates a debug TEE.
    pub fn is_debug(&self) -> bool {
        match self {
            Self::Sgx(report) => report.attributes.flags.contains(AttributesFlags::DEBUG),
            Self::Tdx(report) => report.td_attributes.contains(TdAttributes::DEBUG),
        }
    }

    /// Converts this report into an enclave identity.
    pub fn as_enclave_identity(&self) -> EnclaveIdentity {
        match self {
            Self::Sgx(report) => EnclaveIdentity {
                mr_enclave: MrEnclave::from(report.mrenclave.to_vec()),
                mr_signer: MrSigner::from(report.mrsigner.to_vec()),
            },
            Self::Tdx(report) => report.as_enclave_identity(),
        }
    }

    /// Data contained in the report.
    pub fn report_data(&self) -> Vec<u8> {
        match self {
            Self::Sgx(report) => report.reportdata.to_vec(),
            Self::Tdx(report) => report.report_data.to_vec(),
        }
    }
}

/// Quote signature trait.
pub trait QuoteSignature<'a>: Sized {
    /// Parse the quote signature from the passed data.
    fn parse(version: u16, data: Cow<'a, [u8]>) -> Result<Self, Error>;
}

/// ECDSA-P256 quote signature.
#[derive(Debug)]
pub struct QuoteSignatureEcdsaP256<'a> {
    signature: Cow<'a, [u8]>,
    attestation_public_key: Cow<'a, [u8]>,

    qe: CertificationDataQeReport<'a>,
}

impl<'a> QuoteSignature<'a> for QuoteSignatureEcdsaP256<'a> {
    fn parse(version: u16, mut data: Cow<'a, [u8]>) -> Result<Self, Error> {
        let sig_len = data
            .take_prefix(mem::size_of::<u32>())
            .map(|v| LittleEndian::read_u32(&v))?;
        if sig_len as usize != data.len() {
            return Err(Error::QuoteParseError(
                "unexpected trailing data after signature".to_string(),
            ));
        }
        let signature = data.take_prefix(ECDSA_P256_SIGNATURE_LEN)?;
        let attestation_public_key = data.take_prefix(ECDSA_P256_PUBLIC_KEY_LEN)?;

        // In version 4 quotes, there is an intermediate certification data tuple.
        if version == QUOTE_VERSION_4 {
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

            if certification_data_type != CertificationDataType::QeReport {
                return Err(Error::UnexpectedCertificationData);
            }
        }

        let qe = CertificationDataQeReport::parse(data)?;

        Ok(QuoteSignatureEcdsaP256 {
            signature,
            attestation_public_key,
            qe,
        })
    }
}

impl<'a> QuoteSignatureEcdsaP256<'a> {
    /// Raw signature.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Raw attestation public key.
    pub fn attestation_public_key(&self) -> &[u8] {
        &self.attestation_public_key
    }

    /// Verify signature against quote using the attestation public key.
    ///
    /// The passed `data` must cover the Quote Header and the Report Data.
    pub fn verify_quote_signature(&'a self, data: &[u8]) -> Result<&'a Self, Error> {
        let sig = raw_ecdsa_sig_to_der(self.signature())?;
        let mut pk = parse_ecdsa_pk(self.attestation_public_key())?;

        let mut hash = [0u8; 32];
        Md::hash(hash::Type::Sha256, data, &mut hash).map_err(|err| Error::Other(err.into()))?;
        pk.verify(hash::Type::Sha256, &hash, &sig)
            .map_err(|_| Error::VerificationFailed("quote signature is invalid".to_string()))?;

        Ok(self)
    }

    /// Verify QE Report signature using the PCK public key.
    pub fn verify_qe_report_signature(&self, pck_pk: &[u8]) -> Result<(), Error> {
        self.qe
            .verify_qe_report_signature(self.attestation_public_key(), pck_pk)
    }
}

/// Convert IEEE P1363 ECDSA signature to RFC5480 ASN.1 representation.
fn raw_ecdsa_sig_to_der(sig: &[u8]) -> Result<Vec<u8>, Error> {
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

/// Parse Secp256r1 public key.
fn parse_ecdsa_pk(pk: &[u8]) -> Result<Pk, Error> {
    let mut pt = vec![0x4]; // Add SEC 1 tag (uncompressed).
    pt.extend_from_slice(pk);

    let group = EcGroup::new(EcGroupId::SecP256R1).map_err(|err| Error::Other(err.into()))?;
    let pt = EcPoint::from_binary(&group, &pt).map_err(|err| Error::Other(err.into()))?;
    Pk::public_from_ec_components(group, pt).map_err(|err| Error::Other(err.into()))
}

/// Quote signature verifier for ECDSA-P256 signatures.
pub trait QuoteSignatureEcdsaP256Verifier {
    /// Verify the platform certification data.
    ///
    /// The certification data is in `signature.certification_data()`.
    ///
    /// On success, should return the platform certification public key (PCK) in DER format.
    fn verify_certification_data(
        &mut self,
        signature: &QuoteSignatureEcdsaP256,
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
        verifier.verify_qe(self.qe.qe_report(), self.qe.authentication_data())?;
        self.verify_quote_signature(quote)?;
        Ok(())
    }
}

/// Certification data type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, FromPrimitive, ToPrimitive)]
#[repr(u16)]
pub enum CertificationDataType {
    PpidCleartext = 1,
    PpidEncryptedRsa2048 = 2,
    PpidEncryptedRsa3072 = 3,
    PckCertificate = 4,
    PckCertificateChain = 5,
    QeReport = 6,
    PlatformManifest = 7,
}

/// Certification data trait.
pub trait CertificationData<'a>: Sized {
    /// Parse certification data of the given type from the given raw data.
    fn parse(r#type: CertificationDataType, data: Cow<'a, [u8]>) -> Result<Self, Error>;
}

/// PPID certification data.
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

/// PCK certificate chain certification data.
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

/// QE report certification data.
#[derive(Debug)]
pub struct CertificationDataQeReport<'a> {
    qe_report: Cow<'a, [u8]>,
    qe_report_signature: Cow<'a, [u8]>,
    authentication_data: Cow<'a, [u8]>,
    certification_data_type: CertificationDataType,
    certification_data: Cow<'a, [u8]>,
}

impl<'a> CertificationDataQeReport<'a> {
    fn parse(mut data: Cow<'a, [u8]>) -> Result<Self, Error> {
        let qe_report = data.take_prefix(SGX_REPORT_BODY_LEN)?;
        let qe_report_signature = data.take_prefix(ECDSA_P256_SIGNATURE_LEN)?;
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

        Ok(CertificationDataQeReport {
            qe_report,
            qe_report_signature,
            authentication_data,
            certification_data_type,
            certification_data: data,
        })
    }

    /// Raw QE report.
    pub fn qe_report(&self) -> &[u8] {
        &self.qe_report
    }

    /// Raw QE report signature.
    pub fn qe_report_signature(&self) -> &[u8] {
        &self.qe_report_signature
    }

    /// Raw authentication data.
    pub fn authentication_data(&self) -> &[u8] {
        &self.authentication_data
    }

    /// Inner certification data type.
    pub fn certification_data_type(&self) -> CertificationDataType {
        self.certification_data_type
    }

    /// Parse inner certification data.
    pub fn certification_data<T: CertificationData<'a>>(&self) -> Result<T, Error> {
        T::parse(
            self.certification_data_type,
            self.certification_data.clone(),
        )
    }

    /// Verify QE Report signature using the PCK public key.
    pub fn verify_qe_report_signature(
        &self,
        attestation_pk: &[u8],
        pck_pk: &[u8],
    ) -> Result<(), Error> {
        // Verify QE report signature using PCK public key.
        let sig = raw_ecdsa_sig_to_der(self.qe_report_signature())?;
        let mut hash = [0u8; 32];
        Md::hash(hash::Type::Sha256, self.qe_report(), &mut hash)
            .map_err(|err| Error::Other(err.into()))?;
        let mut pck_pk = Pk::from_public_key(pck_pk).map_err(|err| Error::Other(err.into()))?;
        pck_pk
            .verify(mbedtls::hash::Type::Sha256, &hash, &sig)
            .map_err(|_| Error::VerificationFailed("QE report signature is invalid".to_string()))?;

        // Verify QE report data. First 32 bytes MUST be:
        //   SHA-256(AttestationPublicKey || AuthenticationData)
        // and the remaining 32 bytes MUST be zero.
        let mut hash = [0u8; 32];
        let mut sha256 = Md::new(hash::Type::Sha256).map_err(|err| Error::Other(err.into()))?;
        sha256
            .update(attestation_pk)
            .map_err(|err| Error::Other(err.into()))?;
        sha256
            .update(self.authentication_data())
            .map_err(|err| Error::Other(err.into()))?;
        sha256
            .finish(&mut hash)
            .map_err(|err| Error::Other(err.into()))?;

        let mut qe_report = Vec::with_capacity(SgxReport::UNPADDED_SIZE);
        qe_report.extend(self.qe_report());
        qe_report.resize_with(SgxReport::UNPADDED_SIZE, Default::default);
        let qe_report = SgxReport::try_copy_from(&qe_report).ok_or(Error::MalformedQEReport)?;

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

/// Quoting Enclave ECDSA P-256 verifier.
pub struct QeEcdsaP256Verifier {
    tcb_info: TCBInfo,
    qe_identity: QEIdentity,
    tdx_comp_svn: Option<[u32; 16]>,
    tcb_level: Option<TCBLevel>,
}

impl QeEcdsaP256Verifier {
    /// Create a new verifier.
    pub fn new(
        tcb_info: TCBInfo,
        qe_identity: QEIdentity,
        tdx_comp_svn: Option<[u32; 16]>,
    ) -> Self {
        Self {
            tcb_info,
            qe_identity,
            tdx_comp_svn,
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
            .qe
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
        let tcb_level = self.tcb_info.verify(
            &fmspc.unwrap(),
            &tcb_comp_svn.unwrap(),
            self.tdx_comp_svn.as_ref(),
            pcesvn.unwrap(),
        )?;
        self.tcb_level = Some(tcb_level);

        // Extract PCK public key.
        let pck_pk = pck_cert
            .public_key_mut()
            .write_public_der_vec()
            .map_err(|_| Error::MalformedPCK)?;

        Ok(pck_pk)
    }

    fn verify_qe(&mut self, qe_report: &[u8], _authentication_data: &[u8]) -> Result<(), Error> {
        let mut report = Vec::with_capacity(SgxReport::UNPADDED_SIZE);
        report.extend(qe_report);
        report.resize_with(SgxReport::UNPADDED_SIZE, Default::default);

        let report = SgxReport::try_copy_from(&report).ok_or(Error::MalformedQEReport)?;
        self.qe_identity.verify(&report)?;

        Ok(())
    }
}
