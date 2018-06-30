//! X509 certificate generation from Ed25519 keys.
use std::convert::TryFrom;

#[cfg(not(target_env = "sgx"))]
use grpcio;

use ekiden_common_api as api;

use super::bytes::{B256, B64};
use super::error::{Error, Result};
use super::signature::{Signature, Signer};

/// Common name used for generated certificates.
pub const CERTIFICATE_COMMON_NAME: &'static str = "ekiden-node";
/// Signature context used for certificate public keys.
pub const CERTIFICATE_SIGNATURE_CONTEXT: B64 = B64(*b"EkTlsPub");

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
    /// Validate PEM-encoded X509 certificate and extract node Ed25519 public key.
    #[cfg(not(target_env = "sgx"))]
    pub fn validate_pem(pem: String) -> Result<B256> {
        use openssl::nid::Nid;
        use openssl::x509::X509;

        let certificate = X509::from_pem(pem.as_bytes())?;

        // Ensure common name is CERTIFICATE_COMMON_NAME.
        if let Some(cn) = certificate
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
        {
            if cn.data().as_slice() != CERTIFICATE_COMMON_NAME.as_bytes() {
                return Err(Error::new("invalid certificate subject common name"));
            }
        } else {
            return Err(Error::new("missing certificate subject common name"));
        }

        // Extract P-256 EC public key.
        let key = certificate.public_key()?.public_key_to_der()?;
        // Extract and verify signature of the public key.
        let raw_signature = certificate.serial_number().to_bn()?.to_vec();
        if raw_signature.len() != 96 {
            return Err(Error::new("invalid certificate node signature"));
        }

        let signature = Signature {
            public_key: raw_signature[..32].into(),
            signature: raw_signature[32..96].into(),
            attestation: None,
        };

        if !signature.verify(&CERTIFICATE_SIGNATURE_CONTEXT, &key) {
            return Err(Error::new("invalid certificate node signature"));
        }

        Ok(signature.public_key)
    }

    /// Generate a new self-signed X509 certificate.
    ///
    /// A new NIST P-256 EC key pair is generated for use in this certificate.
    #[cfg(not(target_env = "sgx"))]
    pub fn generate(signer: &Signer) -> Result<(Certificate, PrivateKey)> {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
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

        // Encode Ed25519 node public key signature by node's Ed25519 public key in serial number.
        // TODO: This is currently needed because the X509 API exposes no way to parse extensions.
        let signature = Signature::sign(
            signer,
            &CERTIFICATE_SIGNATURE_CONTEXT,
            &key.public_key_to_der()?,
        );
        let mut raw_signature = vec![0; 96];
        raw_signature[..32].clone_from_slice(&signature.public_key);
        raw_signature[32..].clone_from_slice(&signature.signature);

        let serial = BigNum::from_slice(&raw_signature)?;
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

/// Authenticate current request and return caller's public key.
///
/// This assumes that the TLS connection that is used for gRPC uses a node certificate
/// generated from the node's Ed25519 key pair (e.g., using `Certificate`).
#[cfg(not(target_env = "sgx"))]
pub fn get_node_id(ctx: &grpcio::RpcContext) -> Result<B256> {
    let auth_context = ctx.auth_context();
    for property in auth_context.iter() {
        if property.name() == "x509_pem_cert" {
            return Ok(Certificate::validate_pem(property.value())?);
        }
    }

    return Err(Error::new("request not authenticated"));
}
