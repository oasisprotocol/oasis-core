use io_context::Context as IoContext;

use oasis_core_runtime::{
    common::crypto::mrae::deoxysii::{DeoxysII, KEY_SIZE, NONCE_SIZE, TAG_SIZE},
    storage::MKVS,
};

/// A keyed storage encryption context, for use with a MKVS instance.
pub struct EncryptionContext {
    d2: DeoxysII,
}

impl EncryptionContext {
    /// Initialize a new EncryptionContext with the given MRAE key.
    pub fn new(key: &[u8]) -> Self {
        assert!(
            key.len() == KEY_SIZE,
            "mkvs: invalid encryption key size {}",
            key.len()
        );
        let mut raw_key = [0u8; KEY_SIZE];
        raw_key.copy_from_slice(&key[..KEY_SIZE]);

        let d2 = DeoxysII::new(&raw_key);
        //raw_key.zeroize();

        Self { d2 }
    }

    /// Get encrypted MKVS entry.
    pub fn get(&self, mkvs: &dyn MKVS, ctx: IoContext, key: &[u8]) -> Option<Vec<u8>> {
        let key = self.derive_encrypted_key(key);
        let ciphertext = match mkvs.get(ctx, &key) {
            Some(ciphertext) => ciphertext,
            None => return None,
        };

        self.open(&ciphertext)
    }

    /// Insert encrypted MKVS entry.
    pub fn insert(
        &self,
        mkvs: &mut dyn MKVS,
        ctx: IoContext,
        key: &[u8],
        value: &[u8],
        nonce: &[u8],
    ) -> Option<Vec<u8>> {
        let nonce = Self::derive_nonce(nonce);
        let mut ciphertext = self.d2.seal(&nonce, value, vec![]);
        ciphertext.extend_from_slice(&nonce);

        let key = self.derive_encrypted_key(key);
        let ciphertext = match mkvs.insert(ctx, &key, &ciphertext) {
            Some(ciphertext) => ciphertext,
            None => return None,
        };

        self.open(&ciphertext)
    }

    /// Remove encrypted MKVS entry.
    pub fn remove(&self, mkvs: &mut dyn MKVS, ctx: IoContext, key: &[u8]) -> Option<Vec<u8>> {
        let key = self.derive_encrypted_key(key);
        let ciphertext = match mkvs.remove(ctx, &key) {
            Some(ciphertext) => ciphertext,
            None => return None,
        };

        self.open(&ciphertext)
    }

    fn open(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        // ciphertext || tag || nonce.
        if ciphertext.len() < TAG_SIZE + NONCE_SIZE {
            return None;
        }

        let nonce_offset = ciphertext.len() - NONCE_SIZE;
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&ciphertext[nonce_offset..]);
        let ciphertext = &ciphertext[..nonce_offset];

        let plaintext = self.d2.open(&nonce, ciphertext.to_vec(), vec![]);
        plaintext.ok()
    }

    fn derive_encrypted_key(&self, key: &[u8]) -> Vec<u8> {
        // XXX: The plan is eventually to use a lighter weight transform
        // for the key instead of a full fledged MRAE algorithm.  For now
        // approximate it with a Deoxys-II call with an all 0 nonce.

        let nonce = [0u8; NONCE_SIZE];
        // XXX: Prefix all keys by 0x01 to make sure they do not clash with pending messages.
        let mut pkey = vec![0x01];
        pkey.append(&mut self.d2.seal(&nonce, key, vec![]));
        pkey
    }

    fn derive_nonce(nonce: &[u8]) -> [u8; NONCE_SIZE] {
        // Just a copy for type safety.
        let mut n = [0u8; NONCE_SIZE];
        assert!(
            nonce.len() == NONCE_SIZE,
            "invalid nonce size: {}",
            nonce.len()
        );

        n.copy_from_slice(nonce);

        n
    }
}
