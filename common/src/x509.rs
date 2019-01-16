//! X509 certificate generation from Ed25519 keys.
// TODO: Remove this when it is no longer being used by the key manager node.
use std::convert::TryFrom;

use ekiden_common_api as api;

use super::error::{Error, Result};

/// Common name used for generated certificates.
pub const CERTIFICATE_COMMON_NAME: &'static str = "ekiden-node";

/// Private key associated with a certificate.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct PrivateKey {
    /// DER-encoded private key.
    der: Vec<u8>,
}

impl PrivateKey {
    /// Return the DER-encoded private key.
    pub fn get_der(&self) -> &[u8] {
        &self.der
    }

    /// Return the PEM-encoded private key.
    #[cfg(not(target_env = "sgx"))]
    pub fn get_pem(&self) -> Result<Vec<u8>> {
        use openssl::pkey::PKey;

        let key = PKey::private_key_from_der(&self.der)?;
        Ok(key.private_key_to_pem_pkcs8()?)
    }
}

/// X509 certificate.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    /// DER-encoded certificate.
    der: Vec<u8>,
}

impl Certificate {
    /// Generate a new self-signed X509 certificate.
    ///
    /// A new NIST P-256 EC key pair is generated for use in this certificate.
    #[cfg(not(target_env = "sgx"))]
    pub fn generate() -> Result<(Certificate, PrivateKey)> {
        use openssl::asn1::Asn1Time;
        use openssl::bn::{BigNum, MsbOption};
        use openssl::ec::{Asn1Flag, EcGroup, EcKey};
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage,
                                       KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier};
        use openssl::x509::{X509, X509Name};

        // Generate key pair used for the X509 certificate.
        let mut group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        group.set_asn1_flag(Asn1Flag::NAMED_CURVE);
        let key = EcKey::generate(&group)?;
        let key = PKey::from_ec_key(key)?;

        // Build name included in certificate.
        let mut name = X509Name::builder()?;
        name.append_entry_by_nid(Nid::COMMONNAME, CERTIFICATE_COMMON_NAME)?;
        let name = name.build();

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
        builder.set_pubkey(&key)?;

        let mut serial = BigNum::new()?;
        serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
        builder.set_serial_number(serial.to_asn1_integer()?.as_ref())?;

        let basic_constraints = BasicConstraints::new().critical().ca().build()?;
        builder.append_extension(basic_constraints)?;
        let key_usage = KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .key_cert_sign()
            .build()?;
        builder.append_extension(key_usage)?;
        let ext_key_usage = ExtendedKeyUsage::new().client_auth().server_auth().build()?;
        builder.append_extension(ext_key_usage)?;
        let subject_key_identifier =
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
        builder.append_extension(subject_key_identifier)?;
        let authority_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(None, None))?;
        builder.append_extension(authority_key_identifier)?;
        let subject_alternative_name = SubjectAlternativeName::new()
            .dns(CERTIFICATE_COMMON_NAME)
            .build(&builder.x509v3_context(None, None))?;
        builder.append_extension(subject_alternative_name)?;

        builder.sign(&key, MessageDigest::sha256())?;

        let certificate = builder.build();

        Ok((
            Certificate {
                der: certificate.to_der()?,
            },
            PrivateKey {
                der: key.private_key_to_der()?,
            },
        ))
    }

    /// Return the DER-encoded certificate.
    pub fn get_der(&self) -> &[u8] {
        &self.der
    }

    /// Return the PEM-encoded certificate.
    #[cfg(not(target_env = "sgx"))]
    pub fn get_pem(&self) -> Result<Vec<u8>> {
        use openssl::x509::X509;

        let certificate = X509::from_der(&self.der)?;
        Ok(certificate.to_pem()?)
    }
}

impl TryFrom<api::Certificate> for Certificate {
    type Error = Error;

    fn try_from(mut certificate: api::Certificate) -> Result<Self> {
        Ok(Certificate {
            der: certificate.take_der(),
        })
    }
}

impl Into<api::Certificate> for Certificate {
    fn into(self) -> api::Certificate {
        let mut certificate = api::Certificate::new();
        certificate.set_der(self.der);
        certificate
    }
}

#[cfg(test)]
mod test {
    use super::Certificate;

    #[test]
    fn test_x509_serialization() {
        let (tls_certificate, _) = Certificate::generate().unwrap();
        String::from_utf8(tls_certificate.get_pem().unwrap()).unwrap();
    }
}
