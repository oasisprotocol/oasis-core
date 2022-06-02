//! Transaction I/O tree.
use anyhow::{anyhow, Result};
use io_context::Context;

use super::tags::Tags;
use crate::{
    common::{crypto::hash::Hash, key_format::KeyFormat},
    storage::mkvs::{self, sync::ReadSync, Root, WriteLog},
};

// NOTE: This should be kept in sync with go/runtime/transaction/transaction.go.

#[derive(Debug)]
#[repr(u8)]
enum ArtifactKind {
    Input = 1,
    Output = 2,
}

// Workaround because rust doesn't support `as u8` inside match arms.
// See https://github.com/rust-lang/rust/issues/44266
const ARTIFACT_KIND_INPUT: u8 = ArtifactKind::Input as u8;
const ARTIFACT_KIND_OUTPUT: u8 = ArtifactKind::Output as u8;

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
        b'T'
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

/// Hash used for block emitted tags not tied to a specific transaction.
pub const TAG_BLOCK_TX_HASH: Hash = Hash([0u8; 32]);

impl KeyFormat for TagKeyFormat {
    fn prefix() -> u8 {
        b'E'
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
#[derive(Clone, Debug, Default, PartialEq, cbor::Encode, cbor::Decode)]
#[cbor(as_array)]
struct InputArtifacts {
    /// Transaction input.
    pub input: Vec<u8>,
    /// Transaction order within the batch.
    ///
    /// This is only relevant within the committee that is processing the batch
    /// and should be ignored once transactions from multiple committees are
    /// merged together.
    pub batch_order: u32,
}

/// The output transaction artifacts.
///
/// These are the artifacts that are stored CBOR-serialized in the Merkle tree.
#[derive(Clone, Debug, Default, PartialEq, cbor::Encode, cbor::Decode)]
#[cbor(as_array)]
struct OutputArtifacts {
    /// Transaction output.
    pub output: Vec<u8>,
}

/// A Merkle tree containing transaction artifacts.
pub struct Tree {
    io_root: Root,
    tree: mkvs::OverlayTree<mkvs::Tree>,
}

impl Tree {
    /// Create a new transaction artifacts tree.
    pub fn new(read_syncer: Box<dyn ReadSync>, io_root: Root) -> Self {
        Self {
            io_root,
            tree: mkvs::OverlayTree::new(
                mkvs::Tree::builder().with_root(io_root).build(read_syncer),
            ),
        }
    }

    /// Add an input transaction artifact.
    pub fn add_input(&mut self, ctx: Context, input: Vec<u8>, batch_order: u32) -> Result<()> {
        if input.is_empty() {
            return Err(anyhow!("transaction: no input given"));
        }

        let tx_hash = Hash::digest_bytes(&input);

        self.tree.insert(
            ctx,
            &TxnKeyFormat {
                tx_hash,
                kind: ArtifactKind::Input,
            }
            .encode(),
            &cbor::to_vec(InputArtifacts { input, batch_order }),
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
    ) -> Result<()> {
        let ctx = ctx.freeze();

        self.tree.insert(
            Context::create_child(&ctx),
            &TxnKeyFormat {
                tx_hash,
                kind: ArtifactKind::Output,
            }
            .encode(),
            &cbor::to_vec(OutputArtifacts { output }),
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

    /// Add block tags.
    pub fn add_block_tags(&mut self, ctx: Context, tags: Tags) -> Result<()> {
        let ctx = ctx.freeze();

        for tag in tags {
            self.tree.insert(
                Context::create_child(&ctx),
                &TagKeyFormat {
                    key: tag.key,
                    tx_hash: TAG_BLOCK_TX_HASH,
                }
                .encode(),
                &tag.value,
            )?;
        }

        Ok(())
    }

    /// Commit updates to the underlying Merkle tree and return the write
    /// log and root hash.
    pub fn commit(&mut self, ctx: Context) -> Result<(WriteLog, Hash)> {
        self.tree
            .commit_both(ctx, self.io_root.namespace, self.io_root.version)
    }
}

#[cfg(test)]
mod test {
    use io_context::Context;

    use crate::storage::mkvs::sync::*;

    use super::{super::tags::Tag, *};

    #[test]
    fn test_transaction() {
        let mut tree = Tree::new(
            Box::new(NoopReadSyncer),
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
            "8399ffa753987b00ec6ab251337c6b88e40812662ed345468fcbf1dbdd16321c",
        );
    }
}
