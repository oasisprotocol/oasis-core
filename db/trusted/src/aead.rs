//! Storage mapper that performs transparent authenticated encryption.
use std::sync::Arc;

use serde_cbor;

use ekiden_common::error::Result;
use ekiden_common::ring::{aead, digest};
use ekiden_storage_base::{StorageBackend, StorageMapper};

/// Structure used to store encrypted data.
#[derive(Deserialize, Serialize)]
struct AeadBox {
    /// Random nonce.
    nonce: [u8; 12],
    /// Data.
    data: Vec<u8>,
}

/// Storage mapper that performs transparent authenticated encryption.
pub struct AeadStorageMapper {
    /// Parent storage mapper.
    parent: Arc<StorageMapper>,
    /// State opening key.
    opening_key: Arc<aead::OpeningKey>,
    /// State sealing key.
    sealing_key: Arc<aead::SealingKey>,
    /// Nonce.
    nonce: Vec<u8>,
}

impl AeadStorageMapper {
    /// Create new AEAD storage mapper.
    pub fn new(parent: Arc<StorageMapper>, key: Vec<u8>, nonce: Vec<u8>) -> Self {
        Self {
            parent,
            opening_key: Arc::new(aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &key).unwrap()),
            sealing_key: Arc::new(aead::SealingKey::new(&aead::CHACHA20_POLY1305, &key).unwrap()),
            nonce,
        }
    }

    /// Return length of key that needs to be passed to the constructor.
    pub fn key_len() -> usize {
        aead::CHACHA20_POLY1305.key_len()
    }
}

impl StorageMapper for AeadStorageMapper {
    fn backend(&self) -> &StorageBackend {
        self.parent.backend()
    }

    fn map_get(&self) -> Box<Fn(Vec<u8>) -> Result<Vec<u8>> + Send + Sync> {
        let opening_key = self.opening_key.clone();

        Box::new(move |value| {
            // Open encrypted data from untrusted transfer buffer.
            let mut value: AeadBox = serde_cbor::from_slice(&value)?;
            let value_len =
                aead::open_in_place(&opening_key, &value.nonce, &[], 0, &mut value.data)?.len();
            value.data.truncate(value_len);

            Ok(value.data)
        })
    }

    fn map_insert(&self) -> Box<Fn(Vec<u8>) -> Result<Vec<u8>> + Send + Sync> {
        let sealing_key = self.sealing_key.clone();
        let nonce = self.nonce.clone();

        Box::new(move |value| {
            let mut value = AeadBox {
                nonce: [0; 12],
                data: value,
            };

            // Generate nonce.
            // TODO: Use a proper MRAE scheme (e.g., AES-GCM-SIV).
            let mut ctx = digest::Context::new(&digest::SHA512_256);
            ctx.update(&nonce);
            ctx.update(&value.data);
            value.nonce.clone_from_slice(&ctx.finish().as_ref()[..12]);

            // Seal data.
            let tag_len = sealing_key.algorithm().tag_len();
            let data_len = value.data.len();
            value.data.resize(data_len + tag_len, 0);
            let out_len =
                aead::seal_in_place(&sealing_key, &value.nonce, &[], &mut value.data, tag_len)?;
            value.data.resize(out_len, 0);

            Ok(serde_cbor::to_vec(&value)?)
        })
    }
}
