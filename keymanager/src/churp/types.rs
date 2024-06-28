//! CHURP types used by the worker-host protocol.
use std::convert::{TryFrom, TryInto};

use group::{ff::PrimeField, Group, GroupEncoding};
use zeroize::Zeroize;

use oasis_core_runtime::{
    common::{
        crypto::{
            hash::Hash,
            signature::{PublicKey, Signature},
        },
        namespace::Namespace,
    },
    consensus::beacon::EpochTime,
};

use secret_sharing::{
    churp::{SecretShare, VerifiableSecretShare},
    vss::{
        matrix::VerificationMatrix,
        polynomial::{EncryptedPoint, Polynomial},
        scalar::{scalar_from_bytes, scalar_to_bytes},
    },
};

use crate::crypto::KeyPairId;

use super::Error;

/// Handoff request.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct HandoffRequest {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// The epoch of the handoff.
    pub epoch: EpochTime,
}

/// Handoff query.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct QueryRequest {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// The epoch of the handoff.
    pub epoch: EpochTime,

    /// The public key of the node making the query.
    #[cbor(optional)]
    pub node_id: Option<PublicKey>,
}

/// Fetch handoff data request.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct FetchRequest {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// The epoch of the handoff.
    pub epoch: EpochTime,

    /// The public keys of nodes from which to fetch data.
    pub node_ids: Vec<PublicKey>,
}

/// Fetch handoff data response.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct FetchResponse {
    /// Indicates whether the data fetching was completed.
    pub completed: bool,

    /// Public keys of nodes from which data was successfully fetched.
    pub succeeded: Vec<PublicKey>,

    /// Public keys of nodes from which data failed to be fetched.
    pub failed: Vec<PublicKey>,
}

/// Node's application to form a new committee.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct ApplicationRequest {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// The epoch of the handoff for which the node would like to register.
    pub epoch: EpochTime,

    /// Checksum is the hash of the verification matrix.
    pub checksum: Hash,
}

/// An application request signed by the key manager enclave using its
/// runtime attestation key (RAK).
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct SignedApplicationRequest {
    /// Application request.
    pub application: ApplicationRequest,

    /// RAK signature of the application request.
    pub signature: Signature,
}

/// Confirmation that the node successfully reconstructed the share.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct ConfirmationRequest {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// The epoch of the handoff for which the node reconstructed the share.
    pub epoch: EpochTime,

    /// Checksum is the hash of the verification matrix.
    pub checksum: Hash,
}

/// A confirmation request signed by the key manager enclave using its
/// runtime attestation key (RAK).
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct SignedConfirmationRequest {
    /// Confirmation request.
    pub confirmation: ConfirmationRequest,

    /// RAK signature of the confirmation request.
    pub signature: Signature,
}

/// Key share request.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct KeyShareRequest {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// The epoch of the handoff.
    pub epoch: EpochTime,

    /// The identifier of the runtime for which the key share is requested.
    pub key_runtime_id: Namespace,

    /// The identifier of the key.
    pub key_id: KeyPairId,
}

/// Encoded verifiable secret share.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct EncodedVerifiableSecretShare {
    /// Encoded secret share.
    pub share: EncodedSecretShare,

    /// Encoded verification matrix.
    pub verification_matrix: Vec<u8>,
}

impl<G> From<&VerifiableSecretShare<G>> for EncodedVerifiableSecretShare
where
    G: Group + GroupEncoding,
{
    fn from(verifiable_share: &VerifiableSecretShare<G>) -> Self {
        Self {
            share: verifiable_share.secret_share().into(),
            verification_matrix: verifiable_share.verification_matrix().to_bytes(),
        }
    }
}

impl<G> TryFrom<EncodedVerifiableSecretShare> for VerifiableSecretShare<G>
where
    G: Group + GroupEncoding,
{
    type Error = Error;

    fn try_from(encoded: EncodedVerifiableSecretShare) -> Result<Self, Self::Error> {
        let share = encoded.share.try_into()?;
        let vm = VerificationMatrix::from_bytes(&encoded.verification_matrix)
            .ok_or(Error::VerificationMatrixDecodingFailed)?;
        let verifiable_share = VerifiableSecretShare::new(share, vm);
        Ok(verifiable_share)
    }
}

/// Encoded secret share.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct EncodedSecretShare {
    /// Encoded identity.
    pub x: Vec<u8>,

    /// Encoded polynomial.
    pub polynomial: Vec<u8>,
}

impl<F> From<&SecretShare<F>> for EncodedSecretShare
where
    F: PrimeField,
{
    fn from(share: &SecretShare<F>) -> Self {
        Self {
            x: scalar_to_bytes(share.coordinate_x()),
            polynomial: share.polynomial().to_bytes(),
        }
    }
}

impl<F> TryFrom<EncodedSecretShare> for SecretShare<F>
where
    F: PrimeField,
{
    type Error = Error;

    fn try_from(encoded: EncodedSecretShare) -> Result<Self, Self::Error> {
        let x = scalar_from_bytes(&encoded.x).ok_or(Error::IdentityDecodingFailed)?;
        let p =
            Polynomial::from_bytes(&encoded.polynomial).ok_or(Error::PolynomialDecodingFailed)?;
        let share = SecretShare::new(x, p);
        Ok(share)
    }
}

/// Encoded encrypted point.
#[derive(Clone, Default, cbor::Encode, cbor::Decode, Zeroize)]
pub struct EncodedEncryptedPoint {
    /// Encoded x-coordinate.
    pub x: Vec<u8>,

    /// Encoded y-coordinate in encrypted form.
    pub z: Vec<u8>,
}

impl<G> From<&EncryptedPoint<G>> for EncodedEncryptedPoint
where
    G: Group + GroupEncoding,
{
    fn from(point: &EncryptedPoint<G>) -> Self {
        Self {
            x: scalar_to_bytes(point.x()),
            z: point.z().to_bytes().as_ref().to_vec(),
        }
    }
}

impl<G> TryFrom<EncodedEncryptedPoint> for EncryptedPoint<G>
where
    G: Group + GroupEncoding,
{
    type Error = Error;

    fn try_from(encoded: EncodedEncryptedPoint) -> Result<Self, Self::Error> {
        let x = scalar_from_bytes(&encoded.x).ok_or(Error::IdentityDecodingFailed)?;

        let mut repr: G::Repr = Default::default();
        let slice = &mut repr.as_mut()[..];
        slice.copy_from_slice(&encoded.z);

        let z = match G::from_bytes(&repr).into() {
            None => return Err(Error::IdentityDecodingFailed),
            Some(z) => z,
        };

        let point = EncryptedPoint::new(x, z);
        Ok(point)
    }
}
