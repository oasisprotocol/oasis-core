//! Transaction type.
use ekiden_common::bytes::H256;
use ekiden_common::rlp::{Decodable, DecoderError, Encodable, RlpStream, UntrustedRlp};

/// Transaction (contract invocation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// Contract input.
    pub input: Vec<u8>,
    /// Hash over contract output.
    pub output_hash: H256,
}

impl Encodable for Transaction {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(2);
        stream.append(&self.input);
        stream.append(&self.output_hash);
    }
}

impl Decodable for Transaction {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            input: rlp.val_at(0)?,
            output_hash: rlp.val_at(1)?,
        })
    }
}
