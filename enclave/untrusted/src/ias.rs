use sgx_types;

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

use base64;
use reqwest;

use ekiden_core::bytes::H128;
use ekiden_core::enclave::api as identity_api;
use ekiden_core::error::{Error, Result};

use super::identity;

/// Intel IAS API URL.
const IAS_API_URL: &'static str = "https://test-as.sgx.trustedservices.intel.com";
/// Intel IAS report endpoint.
///
/// See [https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf].
const IAS_ENDPOINT_REPORT: &'static str = "/attestation/sgx/v2/report";

// SPID.
pub type SPID = H128;

/// IAS configuration.
///
/// The `spid` is a valid SPID obtained from Intel, while `pkcs12_archive`
/// is the path to the PKCS#12 archive (certificate and private key), which
/// will be used to authenticate to IAS.
#[derive(Clone, Debug)]
pub struct IASConfiguration {
    /// SPID assigned by Intel.
    pub spid: SPID,
    /// PKCS#12 archive containing the identity for authenticating to IAS.
    pub pkcs12_archive: String,
}

/// IAS (Intel Attestation Service) interface.
#[derive(Clone)]
pub struct IAS {
    /// SPID assigned by Intel.
    spid: sgx_types::sgx_spid_t,
    /// Client used for IAS requests.
    client: Option<reqwest::Client>,
}

impl IAS {
    /// Construct new IAS interface.
    pub fn new(config: Option<IASConfiguration>) -> Result<IAS> {
        match config {
            Some(config) => {
                Ok(IAS {
                    spid: sgx_types::sgx_spid_t {
                        id: config.spid.clone().0,
                    },
                    client: {
                        // Read and parse PKCS#12 archive.
                        let mut buffer = Vec::new();
                        File::open(&config.pkcs12_archive)?.read_to_end(&mut buffer)?;
                        let identity = match reqwest::Identity::from_pkcs12_der(&buffer, "") {
                            Ok(identity) => identity,
                            _ => return Err(Error::new("Failed to load IAS credentials")),
                        };

                        // Create client with the identity.
                        match reqwest::ClientBuilder::new().identity(identity).build() {
                            Ok(client) => Some(client),
                            _ => return Err(Error::new("Failed to create IAS client")),
                        }
                    },
                })
            }
            None => Ok(IAS {
                spid: sgx_types::sgx_spid_t {
                    id: [0; SPID::LENGTH],
                },
                client: None,
            }),
        }
    }

    /// Make authenticated web request to IAS.
    fn make_request(
        &self,
        endpoint: &str,
        data: &HashMap<&str, String>,
    ) -> Result<reqwest::Response> {
        let endpoint = format!("{}{}", IAS_API_URL, endpoint);

        let client = match self.client {
            Some(ref client) => client,
            None => return Err(Error::new("IAS is not configured")),
        };

        match client.post(&endpoint).json(&data).send() {
            Ok(response) => Ok(response),
            _ => return Err(Error::new("Request to IAS failed")),
        }
    }

    /// Make authenticated web request to IAS report endpoint.
    pub fn verify_quote(&self, nonce: &[u8], quote: &[u8]) -> Result<identity_api::AvReport> {
        // Generate mock report when client is not configured.
        if self.client.is_none() {
            let mut av_report = identity_api::AvReport::new();
            av_report.set_body(
                // TODO: Generate other mock fields.
                format!(
                    "{{\"isvEnclaveQuoteStatus\": \"OK\", \"isvEnclaveQuoteBody\": \"{}\"}}",
                    base64::encode(&quote)
                ).into_bytes(),
            );

            return Ok(av_report);
        }

        let mut request = HashMap::new();
        request.insert("isvEnclaveQuote", base64::encode(&quote));
        request.insert("nonce", base64::encode(&nonce));

        let mut response = self.make_request(IAS_ENDPOINT_REPORT, &request)?;
        if !response.status().is_success() {
            return Err(Error::new("Request to IAS failed"));
        }

        let mut av_report = identity_api::AvReport::new();
        av_report.set_body(response.text()?.into_bytes());
        av_report.set_signature(
            response
                .headers()
                .get_raw("X-IASReport-Signature")
                .unwrap()
                .one()
                .unwrap()
                .to_vec(),
        );
        av_report.set_certificates(
            response
                .headers()
                .get_raw("X-IASReport-Signing-Certificate")
                .unwrap()
                .one()
                .unwrap()
                .to_vec(),
        );

        Ok(av_report)
    }
}

impl identity::IAS for IAS {
    fn get_spid(&self) -> &sgx_types::sgx_spid_t {
        &self.spid
    }

    fn get_quote_type(&self) -> sgx_types::sgx_quote_sign_type_t {
        sgx_types::sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE
    }

    fn sigrl(&self, _gid: &sgx_types::sgx_epid_group_id_t) -> Vec<u8> {
        unimplemented!()
    }

    fn report(&self, quote: &[u8]) -> identity_api::AvReport {
        self.verify_quote(&[], quote).expect("IAS::verify_quote")
    }
}
