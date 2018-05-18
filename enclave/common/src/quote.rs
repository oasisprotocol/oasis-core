//! A portable system for parsing and verifying enclave identity proofs.

use std::io::{Cursor, Read, Seek, SeekFrom};
use std::result::Result as StdResult;
use std::time::{SystemTime, UNIX_EPOCH};

use base64;
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::prelude::*;
use pem_iterator::body::Single;
use pem_iterator::boundary::{BoundaryParser, BoundaryType, LabelMatcher};
use percent_encoding;
use serde_json;
use webpki;

use ekiden_common::bytes::H256;
use ekiden_common::error::{Error, Result};
use ekiden_common::untrusted;

use super::api::IdentityProof;

pub const QUOTE_CONTEXT_LEN: usize = 8;
/// The purpose of `QuoteContext` is to prevent quotes from being used in
/// different contexts. The value is included as a prefix in report data.
pub type QuoteContext = [u8; QUOTE_CONTEXT_LEN];

// MRENCLAVE.
pub type MrEnclave = H256;

// AVR signature validation constants.
static IAS_ANCHORS: [webpki::TrustAnchor<'static>; 1] = [
    // Derived via webpki::trust_anchor_util::generate_code_for_trust_anchors.
    //
    // -----BEGIN CERTIFICATE-----
    // MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
    // BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV
    // BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0
    // YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy
    // MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL
    // U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD
    // DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G
    // CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e
    // LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh
    // rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT
    // L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe
    // NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ
    // byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H
    // afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf
    // 6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM
    // RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX
    // MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50
    // L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW
    // BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr
    // NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq
    // hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir
    // IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ
    // sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi
    // zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra
    // Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA
    // 152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB
    // 3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O
    // DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv
    // DaVzWh5aiEx+idkSGMnX
    // -----END CERTIFICATE-----
    webpki::TrustAnchor {
        subject: &[
            49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 67,
            65, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97, 114,
            97, 49, 26, 48, 24, 6, 3, 85, 4, 10, 12, 17, 73, 110, 116, 101, 108, 32, 67, 111, 114,
            112, 111, 114, 97, 116, 105, 111, 110, 49, 48, 48, 46, 6, 3, 85, 4, 3, 12, 39, 73, 110,
            116, 101, 108, 32, 83, 71, 88, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110,
            32, 82, 101, 112, 111, 114, 116, 32, 83, 105, 103, 110, 105, 110, 103, 32, 67, 65,
        ],
        spki: &[
            48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 143, 0, 48, 130, 1,
            138, 2, 130, 1, 129, 0, 159, 60, 100, 126, 181, 119, 60, 187, 81, 45, 39, 50, 192, 215,
            65, 94, 187, 85, 160, 250, 158, 222, 46, 100, 145, 153, 230, 130, 29, 185, 16, 213, 49,
            119, 55, 9, 119, 70, 106, 106, 94, 71, 134, 204, 210, 221, 235, 212, 20, 157, 106, 47,
            99, 37, 82, 157, 209, 12, 201, 135, 55, 176, 119, 156, 26, 7, 226, 156, 71, 161, 174,
            0, 73, 72, 71, 108, 72, 159, 69, 165, 161, 93, 122, 200, 236, 198, 172, 198, 69, 173,
            180, 61, 135, 103, 157, 245, 156, 9, 59, 197, 162, 233, 105, 108, 84, 120, 84, 27, 151,
            158, 117, 75, 87, 57, 20, 190, 85, 211, 47, 244, 192, 157, 223, 39, 33, 153, 52, 205,
            153, 5, 39, 179, 249, 46, 215, 143, 191, 41, 36, 106, 190, 203, 113, 36, 14, 243, 156,
            45, 113, 7, 180, 71, 84, 90, 127, 251, 16, 235, 6, 10, 104, 169, 133, 128, 33, 158, 54,
            145, 9, 82, 104, 56, 146, 214, 165, 226, 168, 8, 3, 25, 62, 64, 117, 49, 64, 78, 54,
            179, 21, 98, 55, 153, 170, 130, 80, 116, 64, 151, 84, 162, 223, 232, 245, 175, 213,
            254, 99, 30, 31, 194, 175, 56, 8, 144, 111, 40, 167, 144, 217, 221, 159, 224, 96, 147,
            155, 18, 87, 144, 197, 128, 93, 3, 125, 245, 106, 153, 83, 27, 150, 222, 105, 222, 51,
            237, 34, 108, 193, 32, 125, 16, 66, 181, 201, 171, 127, 64, 79, 199, 17, 192, 254, 71,
            105, 251, 149, 120, 177, 220, 14, 196, 105, 234, 26, 37, 224, 255, 153, 20, 136, 110,
            242, 105, 155, 35, 91, 180, 132, 125, 214, 255, 64, 182, 6, 230, 23, 7, 147, 194, 251,
            152, 179, 20, 88, 127, 156, 253, 37, 115, 98, 223, 234, 177, 11, 59, 210, 217, 118,
            115, 161, 164, 189, 68, 196, 83, 170, 244, 127, 193, 242, 211, 208, 243, 132, 247, 74,
            6, 248, 156, 8, 159, 13, 166, 205, 183, 252, 238, 232, 201, 130, 26, 142, 84, 242, 92,
            4, 22, 209, 140, 70, 131, 154, 95, 128, 18, 251, 221, 61, 199, 77, 37, 98, 121, 173,
            194, 192, 213, 90, 255, 111, 6, 34, 66, 93, 27, 2, 3, 1, 0, 1,
        ],
        name_constraints: None,
    },
];
static IAS_SIG_ALGS: &'static [&'static webpki::SignatureAlgorithm] =
    &[&webpki::RSA_PKCS1_2048_8192_SHA256];
const PEM_CERTIFICATE_LABEL: &str = "CERTIFICATE";
const IAS_TS_FMT: &str = "%FT%T%.6f";

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
    let avr_body = identity_proof.get_av_report().get_body();
    let unsafe_skip_avr_verification = option_env!("EKIDEN_UNSAFE_SKIP_AVR_VERIFY").is_some();

    // Get the current time.
    //
    // WARNING: If this is running in an enclave, this will be an OCALL, and
    // entirely reliant on the responder to provide the correct time.
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let now_unix = now_unix.as_secs() as i64;

    // Verify IAS signature.
    if !unsafe_skip_avr_verification {
        let avr_cert_chain = identity_proof.get_av_report().get_certificates();
        let avr_signature = identity_proof.get_av_report().get_signature();
        validate_avr_signature(avr_cert_chain, avr_body, avr_signature, now_unix as u64)?;
    }

    // Parse AV report body.
    let avr_body: serde_json::Value = match serde_json::from_slice(avr_body) {
        Ok(avr_body) => avr_body,
        _ => return Err(Error::new("Failed to parse AV report body")),
    };

    // Check timestamp, reject if report is too old (e.g. 1 day).
    if !unsafe_skip_avr_verification {
        let timestamp = match avr_body["timestamp"].as_str() {
            Some(timestamp) => timestamp,
            None => {
                return Err(Error::new("AV report body did not contain timestamp"));
            }
        };
        let timestamp_unix = parse_avr_timestamp(&timestamp)?;
        if (now_unix - timestamp_unix).abs() > 1000 * 60 * 60 * 24 {
            return Err(Error::new("AV report timestamp differs by more than 1 day"));
        }
    }

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

fn parse_avr_timestamp(timestamp: &str) -> Result<i64> {
    let timestamp_unix = match Utc.datetime_from_str(&timestamp, IAS_TS_FMT) {
        Ok(timestamp) => timestamp.timestamp(),
        _ => return Err(Error::new("Failed to parse AV report timestamp")),
    };
    Ok(timestamp_unix)
}

fn validate_avr_signature(
    cert_chain: &[u8],
    message: &[u8],
    signature: &[u8],
    unix_time: u64,
) -> Result<()> {
    // Load the Intel SGX Attestation Report Signing CA certificate.
    let anchors = webpki::TLSServerTrustAnchors(&IAS_ANCHORS);

    // Decode the certificate chain.
    let cert_chain = percent_encoding::percent_decode(cert_chain).decode_utf8()?;
    let cert_chain = pem_parse_many(&cert_chain, PEM_CERTIFICATE_LABEL);
    let cert_chain: Vec<untrusted::Input> = cert_chain
        .iter()
        .map(|contents| untrusted::Input::from(&contents))
        .collect();
    if cert_chain.len() == 0 {
        return Err(Error::new("Unable to find any certificates"));
    }

    // Decode the signature.
    let signature = base64::decode(signature)?;
    let signature = untrusted::Input::from(&signature);

    let message = untrusted::Input::from(&message);
    let time = webpki::Time::from_seconds_since_unix_epoch(unix_time);

    // Do all the actual validation.
    match validate_decoded_avr_signature(&anchors, &cert_chain, message, signature, time) {
        Ok(_) => Ok(()),
        Err(err) => {
            return Err(Error::new(format!(
                "Failed to validate AVR signature: {:?}",
                err
            )))
        }
    }
}

fn validate_decoded_avr_signature(
    anchors: &webpki::TLSServerTrustAnchors,
    cert_ders: &Vec<untrusted::Input>,
    message: untrusted::Input,
    signature: untrusted::Input,
    time: webpki::Time,
) -> StdResult<(), webpki::Error> {
    assert!(cert_ders.len() >= 1);
    let (cert_der, inter_ders) = cert_ders.split_at(1);
    let cert = webpki::EndEntityCert::from(cert_der[0])?;
    cert.verify_is_valid_tls_server_cert(IAS_SIG_ALGS, &anchors, &inter_ders, time)?;
    cert.verify_signature(IAS_SIG_ALGS[0], message, signature)
}

fn pem_parse_many(input: &str, label: &str) -> Vec<Vec<u8>> {
    // This routine superficially mimics the pem crate's pem::parse_many
    // routine with the pem_iterator crate as the former does not build
    // in the SGX enviornment due to dependencies.
    //
    // Invalid PEM will cause the parsing to terminate, and an empty vector
    // to be returned.

    let mut contents = Vec::new();

    let input = input.trim();
    let mut input = input.chars().enumerate();

    loop {
        // Find the begining label.
        {
            let mut parser = BoundaryParser::from_chars(
                BoundaryType::Begin,
                &mut input,
                LabelMatcher(label.chars()),
            );
            if parser.next() != None || parser.complete() != Ok(()) {
                break;
            }
        }

        // Parse the body.
        let data: StdResult<Vec<u8>, _> = Single::from_chars(&mut input).collect();
        let data = match data {
            Ok(data) => data,
            Err(_) => {
                contents.truncate(0);
                break;
            }
        };

        // Find the terminal label.
        {
            let mut parser = BoundaryParser::from_chars(
                BoundaryType::End,
                &mut input,
                LabelMatcher(label.chars()),
            );
            if parser.next() != None || parser.complete() != Ok(()) {
                contents.truncate(0);
                break;
            }
        }

        // The PEM block was well formed, append the data.
        contents.push(data);
    }

    contents
}

#[cfg(test)]
mod tests {
    use super::*;

    const IAS_CERT_CHAIN: &[u8] = include_bytes!("../testdata/avr_certificates_urlencoded.pem");

    #[test]
    fn test_pem_parse_many() {
        let cert_chain = percent_encoding::percent_decode(IAS_CERT_CHAIN)
            .decode_utf8()
            .unwrap();
        let cert_chain = pem_parse_many(&cert_chain, PEM_CERTIFICATE_LABEL);
        assert_eq!(cert_chain.len(), 2);
    }

    #[test]
    fn test_validate_avr_signature() {
        const MSG: &[u8] = include_bytes!("../testdata/avr_body_group_out_of_date.json");
        const SIG: &[u8] = include_bytes!("../testdata/avr_signature_group_out_of_date.sig");
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
