//! Committee node type.
use ekiden_common::bytes::B256;
use ekiden_common::rlp::{Decodable, DecoderError, Encodable, RlpStream, UntrustedRlp};
use ekiden_common::signature::PublicKeyVerifier;

/// Committee node role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// Worker node.
    Worker,
    /// Group leader.
    Leader,
}

impl Encodable for Role {
    fn rlp_append(&self, stream: &mut RlpStream) {
        match *self {
            Role::Worker => stream.encoder().encode_value(&[0]),
            Role::Leader => stream.encoder().encode_value(&[1]),
        }
    }
}

impl Decodable for Role {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        rlp.decoder().decode_value(|bytes| match bytes.len() {
            0 => Err(DecoderError::RlpIsTooShort),
            1 => match bytes[0] {
                0 => Ok(Role::Worker),
                1 => Ok(Role::Leader),
                _ => Err(DecoderError::Custom("Invalid node role")),
            },
            _ => Err(DecoderError::RlpIsTooBig),
        })
    }
}

/// Committee node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeNode {
    /// Node role.
    pub role: Role,
    /// Node public key.
    pub public_key: B256,
}

impl CommitteeNode {
    /// Return signature verifier for this node.
    pub fn get_verifier(&self) -> PublicKeyVerifier {
        PublicKeyVerifier::new(self.public_key.clone())
    }
}

impl Encodable for CommitteeNode {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(2);
        stream.append(&self.role);
        stream.append(&self.public_key);
    }
}

impl Decodable for CommitteeNode {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            role: rlp.val_at(0)?,
            public_key: rlp.val_at(1)?,
        })
    }
}
