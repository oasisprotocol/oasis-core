//! Transaction I/O tree.
use failure::{format_err, Fallible};
use io_context::Context;
use serde::{self, ser::SerializeSeq, Serializer};
use serde_bytes::{self, Bytes};
use serde_derive::Deserialize;

use super::tags::Tags;
use crate::{
    common::{cbor, crypto::hash::Hash, key_format::KeyFormat},
    storage::mkvs::{
        urkel::{sync::ReadSync, Root, UrkelTree},
        WriteLog,
    },
};

// NOTE: This should be kept in sync with go/runtime/transaction/transaction.go.

#[derive(Debug)]
enum ArtifactKind {
    Input,
    Output,
}

const ARTIFACT_KIND_INPUT: u8 = 0;
const ARTIFACT_KIND_OUTPUT: u8 = 1;

/// Key format used for transaction artifacts.
#[derive(Debug)]
struct TxnKeyFormat {
    /// Transaction hash.
    tx_hash: Hash,
    /// Artifact kind.
    kind: ArtifactKind,
}

impl KeyFormat for TxnKeyFormat {
    fn prefix() -> u8 {
        'T' as u8
    }

    fn size() -> usize {
        32 + 1
    }

    fn encode_atoms(self, atoms: &mut Vec<Vec<u8>>) {
        atoms.push(self.tx_hash.as_ref().to_vec());
        match self.kind {
            ArtifactKind::Input => atoms.push(vec![ARTIFACT_KIND_INPUT]),
            ArtifactKind::Output => atoms.push(vec![ARTIFACT_KIND_OUTPUT]),
        }
    }

    fn decode_atoms(data: &[u8]) -> Self {
        Self {
            tx_hash: data[..32].into(),
            kind: match data[32] {
                ARTIFACT_KIND_INPUT => ArtifactKind::Input,
                ARTIFACT_KIND_OUTPUT => ArtifactKind::Output,
                other => panic!("transaction: malformed artifact kind ({:?})", other),
            },
        }
    }
}

/// Key format used for emitted tags.
///
/// This is kept separate so that clients can query only tags they are
/// interested in instead of needing to go through all transactions.
#[derive(Debug, Default)]
struct TagKeyFormat {
    /// Tag key.
    key: Vec<u8>,
    /// Transaction hash of the transaction that emitted the tag.
    tx_hash: Hash,
}

impl KeyFormat for TagKeyFormat {
    fn prefix() -> u8 {
        'E' as u8
    }

    fn size() -> usize {
        32
    }

    fn encode_atoms(self, atoms: &mut Vec<Vec<u8>>) {
        atoms.push(self.key);
        atoms.push(self.tx_hash.as_ref().to_vec());
    }

    fn decode_atoms(data: &[u8]) -> Self {
        let offset = data.len() - Self::size();
        let key = data[0..offset].to_vec();
        let tx_hash = data[offset..].into();

        Self { key, tx_hash }
    }
}

/// The input transaction artifacts.
///
/// These are the artifacts that are stored CBOR-serialized in the Merkle tree.
#[derive(Clone, Debug, PartialEq, Deserialize)]
struct InputArtifacts {
    /// Transaction input.
    #[serde(with = "serde_bytes")]
    pub input: Vec<u8>,
    /// Transaction order within the batch.
    ///
    /// This is only relevant within the committee that is processing the batch
    /// and should be ignored once transactions from multiple committees are
    /// merged together.
    pub batch_order: u32,
}

impl serde::Serialize for InputArtifacts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&Bytes::new(&self.input))?;
        seq.serialize_element(&self.batch_order)?;
        seq.end()
    }
}

/// The output transaction artifacts.
///
/// These are the artifacts that are stored CBOR-serialized in the Merkle tree.
#[derive(Clone, Debug, PartialEq, Deserialize)]
struct OutputArtifacts {
    /// Transaction output.
    #[serde(with = "serde_bytes")]
    pub output: Vec<u8>,
}

impl serde::Serialize for OutputArtifacts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(1))?;
        seq.serialize_element(&Bytes::new(&self.output))?;
        seq.end()
    }
}

/// A Merkle tree containing transaction artifacts.
pub struct Tree {
    io_root: Root,
    tree: UrkelTree,
}

impl Tree {
    /// Create a new transaction artifacts tree.
    pub fn new(read_syncer: Box<dyn ReadSync>, io_root: Root) -> Self {
        Self {
            io_root,
            tree: UrkelTree::make().with_root(io_root).new(read_syncer),
        }
    }

    /// Add an input transaction artifact.
    pub fn add_input(&mut self, ctx: Context, input: Vec<u8>, batch_order: u32) -> Fallible<()> {
        if input.is_empty() {
            return Err(format_err!("transaction: no input given"));
        }

        let tx_hash = Hash::digest_bytes(&input);

        self.tree.insert(
            ctx,
            &TxnKeyFormat {
                tx_hash,
                kind: ArtifactKind::Input,
            }
            .encode(),
            &cbor::to_vec(&InputArtifacts { input, batch_order }),
        )?;

        Ok(())
    }

    /// Add an output transaction artifact.
    pub fn add_output(
        &mut self,
        ctx: Context,
        tx_hash: Hash,
        output: Vec<u8>,
        tags: Tags,
    ) -> Fallible<()> {
        let ctx = ctx.freeze();

        self.tree.insert(
            Context::create_child(&ctx),
            &TxnKeyFormat {
                tx_hash,
                kind: ArtifactKind::Output,
            }
            .encode(),
            &cbor::to_vec(&OutputArtifacts { output }),
        )?;

        // Add tags if specified.
        for tag in tags {
            self.tree.insert(
                Context::create_child(&ctx),
                &TagKeyFormat {
                    key: tag.key,
                    tx_hash,
                }
                .encode(),
                &tag.value,
            )?;
        }

        Ok(())
    }

    /// Commit updates to the underlying Merkle tree and return the write
    /// log and root hash.
    pub fn commit(&mut self, ctx: Context) -> Fallible<(WriteLog, Hash)> {
        self.tree
            .commit(ctx, self.io_root.namespace, self.io_root.round)
    }
}

#[cfg(test)]
mod test {
    use io_context::Context;

    use crate::storage::mkvs::urkel::sync::*;

    use super::{super::tags::Tag, *};

    #[test]
    fn test_transaction() {
        let mut tree = Tree::new(
            Box::new(NoopReadSyncer {}),
            Root {
                hash: Hash::empty_hash(),
                ..Default::default()
            },
        );

        let input = b"this goes in".to_vec();
        let tx_hash = Hash::digest_bytes(&input);
        tree.add_input(Context::background(), input, 0).unwrap();
        tree.add_output(
            Context::background(),
            tx_hash,
            b"and this comes out".to_vec(),
            vec![Tag::new(b"tag1".to_vec(), b"value1".to_vec())],
        )
        .unwrap();

        for i in 0..20 {
            let input = format!("this goes in ({})", i).into_bytes();
            let tx_hash = Hash::digest_bytes(&input);

            tree.add_input(Context::background(), input, i + 1).unwrap();
            tree.add_output(
                Context::background(),
                tx_hash,
                b"and this comes out".to_vec(),
                vec![
                    Tag::new(b"tagA".to_vec(), b"valueA".to_vec()),
                    Tag::new(b"tagB".to_vec(), b"valueB".to_vec()),
                ],
            )
            .unwrap();
        }

        // NOTE: This root is synced with go/runtime/transaction/transaction_test.go.
        let (_, root_hash) = tree.commit(Context::background()).unwrap();
        assert_eq!(
            format!("{:?}", root_hash),
            "4cc8bb6bdb377cc7f1ff8fe972004e1d66fa2c6726ec9e5f870865c190b6a47d"
        );
    }
}
