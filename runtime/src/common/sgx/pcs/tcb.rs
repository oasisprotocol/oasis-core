use std::ffi::CString;

use byteorder::{ByteOrder, LittleEndian};
use chrono::{prelude::*, Duration};
use mbedtls::{alloc::Box as MbedtlsBox, x509::certificate::Certificate};
use rustc_hex::FromHex;
use serde_json::value::RawValue;
use sgx_isa::Report;

use super::{
    certificates::PCS_TRUST_ROOT, constants::*, policy::QuotePolicy, quote::TeeType, Error,
};

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
    pub(super) fn verify_certificates(
        &self,
        _ts: DateTime<Utc>,
    ) -> Result<MbedtlsBox<Certificate>, Error> {
        let raw_certs =
            CString::new(&*self.certificates).map_err(|err| Error::TCBParseError(err.into()))?;
        let mut cert_chain = Certificate::from_pem_multiple(raw_certs.as_bytes_with_nul())
            .map_err(|err| Error::TCBParseError(err.into()))?;
        if cert_chain.iter().count() != 2 {
            return Err(Error::UnexpectedCertificateChain);
        }

        // TODO: Specify current timestamp.
        Certificate::verify(&cert_chain, &PCS_TRUST_ROOT, None, None)
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
    pub fn open(
        &self,
        tee_type: TeeType,
        ts: DateTime<Utc>,
        policy: &QuotePolicy,
        pk: &mut mbedtls::pk::Pk,
    ) -> Result<TCBInfo, Error> {
        let ti: TCBInfo = open_signed_tcb(self.tcb_info.get(), &self.signature, pk)?;
        ti.validate(tee_type, ts, policy)?;

        Ok(ti)
    }
}

/// TCB info identifier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub enum TCBInfoID {
    SGX,
    TDX,
    #[serde(other)]
    #[default]
    Invalid,
}

/// TCB info body.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct TCBInfo {
    #[serde(rename = "id")]
    pub id: TCBInfoID,

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

    #[serde(default, rename = "tdxModule")]
    pub tdx_module: TDXModule,

    #[serde(default, rename = "tdxModuleIdentities")]
    pub tdx_module_identities: Vec<TDXModuleIdentity>,

    #[serde(rename = "tcbLevels")]
    pub tcb_levels: Vec<TCBLevel>,
}

impl TCBInfo {
    /// Validate the TCB info against the quote policy.
    pub fn validate(
        &self,
        tee_type: TeeType,
        ts: DateTime<Utc>,
        policy: &QuotePolicy,
    ) -> Result<(), Error> {
        match (self.id, tee_type) {
            (TCBInfoID::SGX, TeeType::SGX) => {}
            (TCBInfoID::TDX, TeeType::TDX) => {}
            _ => {
                return Err(Error::TCBParseError(anyhow::anyhow!(
                    "unexpected TCB info identifier"
                )))
            }
        }

        if self.version != REQUIRED_TCB_INFO_VERSION {
            return Err(Error::TCBParseError(anyhow::anyhow!(
                "unexpected TCB info version"
            )));
        }

        // Validate TCB info is not expired/not yet valid based on current time.
        let issue_date = NaiveDateTime::parse_from_str(&self.issue_date, PCS_TS_FMT)
            .map_err(|err| Error::TCBParseError(err.into()))?
            .and_utc();
        let _next_update = NaiveDateTime::parse_from_str(&self.next_update, PCS_TS_FMT)
            .map_err(|err| Error::TCBParseError(err.into()))?
            .and_utc();
        if issue_date > ts {
            return Err(Error::TCBExpired);
        }
        if ts - issue_date
            > Duration::try_days(policy.tcb_validity_period.into())
                .unwrap_or(DEFAULT_TCB_VALIDITY_PERIOD)
        {
            return Err(Error::TCBExpired);
        }

        if self.tcb_evaluation_data_number < policy.min_tcb_evaluation_data_number {
            return Err(Error::TCBEvaluationDataNumberInvalid);
        }

        // Validate FMSPC not blacklisted.
        let blocked = policy
            .fmspc_blacklist
            .iter()
            .any(|blocked| blocked == &self.fmspc);
        if blocked {
            return Err(Error::BlacklistedFMSPC);
        }

        Ok(())
    }

    /// Verify and return the TCB level matching the given TCB components and PCESVN.
    pub fn verify(
        &self,
        fmspc: &[u8],
        sgx_comp_svn: &[u32; 16],
        tdx_comp_svn: Option<&[u32; 16]>,
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
            .find(|level| level.matches(sgx_comp_svn, tdx_comp_svn, pcesvn))
            .ok_or(Error::TCBOutOfDate)?
            .clone();

        if self.id == TCBInfoID::TDX {
            // Perform additional TCB status evaluation for TDX module in case TEE TCB SVN at index
            // 1 is greater or equal to 1, otherwise finish the comparison logic.
            let tdx_comp_svn = tdx_comp_svn.ok_or(Error::TCBMismatch)?;
            let tdx_module_version = tdx_comp_svn[1];
            if tdx_module_version >= 1 {
                // In order to determine TCB status of TDX module, find a matching TDX Module
                // Identity (in tdxModuleIdentities array of TCB Info) with its id set to
                // "TDX_<version>" where <version> matches the value of TEE TCB SVN at index 1. If a
                // matching TDX Module Identity cannot be found, fail.
                let tdx_module_id = format!("TDX_{:02}", tdx_module_version);
                let tdx_module = self
                    .tdx_module_identities
                    .iter()
                    .find(|tm| tm.id == tdx_module_id)
                    .ok_or(Error::TCBOutOfDate)?;

                // Otherwise, for the selected TDX Module Identity go over the sorted collection of
                // TCB Levels starting from the first item on the list and compare its isvsvn value
                // to the TEE TCB SVN at index 0. If TEE TCB SVN at index 0 is greater or equal to
                // its value, read tcbStatus assigned to this TCB level, otherwise move to the next
                // item on TCB levels list.
                let tdx_module_level = tdx_module
                    .tcb_levels
                    .iter()
                    .find(|level| level.tcb.isv_svn as u32 <= tdx_comp_svn[0])
                    .ok_or(Error::TCBOutOfDate)?;
                if tdx_module_level.status != TCBStatus::UpToDate {
                    return Err(Error::TCBOutOfDate);
                }
            }
        }

        Ok(level)
    }
}

/// A representation of the properties of Intel's TDX SEAM module.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct TDXModule {
    #[serde(rename = "mrsigner")]
    pub mr_signer: String,

    #[serde(rename = "attributes")]
    pub attributes: String,

    #[serde(rename = "attributesMask")]
    pub attributes_mask: String,
}

/// A representation of the identity of the Intel's TDX SEAM module in case the platform supports
/// more than one TDX SEAM module.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct TDXModuleIdentity {
    #[serde(rename = "id")]
    pub id: String,

    #[serde(flatten)]
    pub module: TDXModule,

    #[serde(rename = "tcbLevels")]
    pub tcb_levels: Vec<EnclaveTCBLevel>,
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
    /// Whether the TCB level matches the given TCB components and PCESVN.
    pub fn matches(
        &self,
        sgx_comp_svn: &[u32],
        tdx_comp_svn: Option<&[u32; 16]>,
        pcesvn: u32,
    ) -> bool {
        // a) Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate (from 01 to
        //    16) with the corresponding values in the TCB Level. If all SGX TCB Comp SVNs in the
        //    certificate are greater or equal to the corresponding values in TCB Level, go to b,
        //    otherwise move to the next item on TCB Levels list.
        for (i, comp) in self.tcb.sgx_components.iter().enumerate() {
            // At least one SVN is lower, no match.
            if sgx_comp_svn[i] < comp.svn {
                return false;
            }
        }

        // b) Compare PCESVN value retrieved from the SGX PCK certificate with the corresponding value
        //    in the TCB Level. If it is greater or equal to the value in TCB Level, read status
        //    assigned to this TCB level (in case of SGX) or go to c (in case of TDX). Otherwise,
        //    move to the next item on TCB Levels list.
        if self.tcb.pcesvn < pcesvn {
            return false;
        }

        if let Some(tdx_comp_svn) = tdx_comp_svn {
            // c) Compare SVNs in TEE TCB SVN array retrieved from TD Report in Quote (from index 0 to
            //    15 if TEE TCB SVN at index 1 is set to 0, or from index 2 to 15 otherwise) with the
            //    corresponding values of SVNs in tdxtcbcomponents array of TCB Level. If all TEE TCB
            //    SVNs in the TD Report are greater or equal to the corresponding values in TCB Level,
            //    read tcbStatus assigned to this TCB level. Otherwise, move to the next item on TCB
            //    Levels list.
            let comps = self.tcb.tdx_components.iter().enumerate();
            let offset = if tdx_comp_svn[1] != 0 { 2 } else { 0 };

            for (i, comp) in comps.skip(offset) {
                // At least one SVN is lower, no match.
                if tdx_comp_svn[i] < comp.svn {
                    return false;
                }
            }
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

    #[serde(rename = "sgxtcbcomponents")]
    pub sgx_components: [TCBComponent; 16],

    #[serde(default, rename = "tdxtcbcomponents")]
    pub tdx_components: [TCBComponent; 16],
}

/// A TCB component.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct TCBComponent {
    #[serde(rename = "svn")]
    pub svn: u32,

    #[serde(default, rename = "category")]
    pub category: String,

    #[serde(default, rename = "type")]
    pub tcb_comp_type: String,
}

/// TCB status.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub enum TCBStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
    #[serde(other)]
    #[default]
    Invalid,
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
    pub fn open(
        &self,
        tee_type: TeeType,
        ts: DateTime<Utc>,
        policy: &QuotePolicy,
        pk: &mut mbedtls::pk::Pk,
    ) -> Result<QEIdentity, Error> {
        let qe: QEIdentity = open_signed_tcb(self.enclave_identity.get(), &self.signature, pk)?;
        qe.validate(tee_type, ts, policy)?;

        Ok(qe)
    }
}

/// QE identity identifier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
#[allow(non_camel_case_types)]
pub enum QEIdentityID {
    QE,
    TD_QE,
    #[serde(other)]
    #[default]
    Invalid,
}

/// QE identity body.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct QEIdentity {
    #[serde(rename = "id")]
    pub id: QEIdentityID,

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

    #[serde(default, rename = "advisoryIDs")]
    pub advisory_ids: Vec<String>,
}

impl QEIdentity {
    /// Validate the QE identity against the quote policy.
    pub fn validate(
        &self,
        tee_type: TeeType,
        ts: DateTime<Utc>,
        policy: &QuotePolicy,
    ) -> Result<(), Error> {
        match (self.id, tee_type) {
            (QEIdentityID::QE, TeeType::SGX) => {}
            (QEIdentityID::TD_QE, TeeType::TDX) => {}
            _ => return Err(Error::TCBParseError(anyhow::anyhow!("unexpected QE ID"))),
        }

        if self.version != REQUIRED_QE_IDENTITY_VERSION {
            return Err(Error::TCBParseError(anyhow::anyhow!(
                "unexpected QE identity version"
            )));
        }

        // Validate QE identity is not expired/not yet valid based on current time.
        let issue_date = NaiveDateTime::parse_from_str(&self.issue_date, PCS_TS_FMT)
            .map_err(|err| Error::TCBParseError(err.into()))?
            .and_utc();
        let _next_update = NaiveDateTime::parse_from_str(&self.next_update, PCS_TS_FMT)
            .map_err(|err| Error::TCBParseError(err.into()))?
            .and_utc();
        if issue_date > ts {
            return Err(Error::TCBExpired);
        }
        if ts - issue_date
            > Duration::try_days(policy.tcb_validity_period.into())
                .unwrap_or(DEFAULT_TCB_VALIDITY_PERIOD)
        {
            return Err(Error::TCBExpired);
        }

        if self.tcb_evaluation_data_number < policy.min_tcb_evaluation_data_number {
            return Err(Error::TCBEvaluationDataNumberInvalid);
        }

        Ok(())
    }

    /// Verify the QE report against the QE identity.
    pub fn verify(&self, report: &Report) -> Result<(), Error> {
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
