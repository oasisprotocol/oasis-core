//! A portable system for parsing and verifying enclave identity proofs.

use std::io::{Cursor, Read, Seek, SeekFrom};
use std::ops::Deref;
use std::str::FromStr;

use base64;
use byteorder::{LittleEndian, ReadBytesExt};
use hex;
use serde_json;

use ekiden_common::error::{Error, Result};
use ekiden_common::hex_encoded_struct;

use super::api::IdentityProof;

pub const QUOTE_CONTEXT_LEN: usize = 8;
/// The purpose of `QuoteContext` is to prevent quotes from being used in
/// different contexts. The value is included as a prefix in report data.
pub type QuoteContext = [u8; QUOTE_CONTEXT_LEN];

// MRENCLAVE.
hex_encoded_struct!(MrEnclave, MRENCLAVE_LEN, 32);

pub fn open_av_report(av_report: &super::api::AvReport) -> Result<serde_json::Value> {
    // TODO: Verify IAS signature.

    // Parse AV report body.
    let avr_body = match serde_json::from_slice(av_report.get_body()) {
        Ok(avr_body) => avr_body,
        _ => return Err(Error::new("Failed to parse AV report body")),
    };

    Ok(avr_body)
}

pub fn get_quote_body_raw(avr_body: &serde_json::Value) -> Result<Vec<u8>> {
    let quote_body = match avr_body["isvEnclaveQuoteBody"].as_str() {
        Some(quote_body) => quote_body,
        None => {
            return Err(Error::new(
                "AV report body did not contain isvEnclaveQuoteBody",
            ))
        }
    };

    let quote_body = match base64::decode(&quote_body) {
        Ok(quote_body) => quote_body,
        _ => return Err(Error::new("Failed to parse quote")),
    };

    Ok(quote_body)
}

pub fn get_platform_info_tlv(avr_body: &serde_json::Value) -> Result<Option<Vec<u8>>> {
    if let Some(platform_info_hex) = avr_body["platformInfoBlob"].as_str() {
        Ok(Some(hex::decode(platform_info_hex)?))
    } else {
        Ok(None)
    }
}

/// Decoded report body.
#[derive(Default, Debug)]
struct ReportBody {
    cpu_svn: [u8; 16],
    misc_select: u32,
    attributes: [u8; 16],
    mr_enclave: MrEnclave,
    mr_signer: [u8; 32],
    isv_prod_id: u16,
    isv_svn: u16,
    report_data: Vec<u8>,
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
    report_body: ReportBody,
}

impl QuoteBody {
    /// Decode quote body.
    fn decode(quote_body: &Vec<u8>) -> Result<QuoteBody> {
        let mut reader = Cursor::new(quote_body);
        let mut quote_body: QuoteBody = QuoteBody::default();

        // TODO: Should we ensure that reserved bytes are all zero?

        // Body.
        quote_body.version = reader.read_u16::<LittleEndian>()?;
        quote_body.signature_type = reader.read_u16::<LittleEndian>()?;
        quote_body.gid = reader.read_u32::<LittleEndian>()?;
        quote_body.isv_svn_qe = reader.read_u16::<LittleEndian>()?;
        quote_body.isv_svn_pce = reader.read_u16::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(4))?; // 4 reserved bytes.
        reader.read_exact(&mut quote_body.basename)?;

        // Report body.
        reader.read_exact(&mut quote_body.report_body.cpu_svn)?;
        quote_body.report_body.misc_select = reader.read_u32::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(28))?; // 28 reserved bytes.
        reader.read_exact(&mut quote_body.report_body.attributes)?;
        reader.read_exact(&mut quote_body.report_body.mr_enclave.0)?;
        reader.seek(SeekFrom::Current(32))?; // 32 reserved bytes.
        reader.read_exact(&mut quote_body.report_body.mr_signer)?;
        reader.seek(SeekFrom::Current(96))?; // 96 reserved bytes.
        quote_body.report_body.isv_prod_id = reader.read_u16::<LittleEndian>()?;
        quote_body.report_body.isv_svn = reader.read_u16::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(60))?; // 60 reserved bytes.
        quote_body.report_body.report_data = vec![0; 64];
        reader.read_exact(&mut quote_body.report_body.report_data)?;

        Ok(quote_body)
    }
}

/// Authenticated information obtained from validating an enclave identity proof.
pub struct IdentityAuthenticatedInfo {
    pub identity: super::identity::PublicIdentityComponents,
    // TODO: add other av report/quote body/report fields we want to give the consumer
    pub mr_enclave: MrEnclave,
}

/// Verify attestation report.
pub fn verify(identity_proof: &IdentityProof) -> Result<IdentityAuthenticatedInfo> {
    let avr_body = open_av_report(identity_proof.get_av_report())?;

    // TODO: Check timestamp, reject if report is too old (e.g. 1 day).

    match avr_body["isvEnclaveQuoteStatus"].as_str() {
        Some(status) => match status {
            "OK" => {}
            _ => {
                return Err(Error::new(format!("Quote status was {}", status)));
            }
        },
        None => {
            return Err(Error::new(
                "AV report body did not contain isvEnclaveQuoteStatus",
            ));
        }
    };

    let quote_body = get_quote_body_raw(&avr_body)?;

    let quote_body = match QuoteBody::decode(&quote_body) {
        Ok(quote_body) => quote_body,
        _ => return Err(Error::new("Failed to parse quote")),
    };

    // TODO: Apply common policy to report body, e.g., check enclave
    // attributes for debug mode.

    // Check report data.
    let public_identity = identity_proof.get_public_identity();
    let report_data_expected = super::identity::pack_report_data(public_identity);
    if &quote_body.report_body.report_data[..] != &report_data_expected.d[..] {
        return Err(Error::new("Report data did not match expected"));
    }

    Ok(IdentityAuthenticatedInfo {
        identity: super::identity::unpack_public_identity(public_identity),
        mr_enclave: quote_body.report_body.mr_enclave,
    })
}
