//! Hash type.
use sha2::{Digest, Sha512Trunc256};

impl_bytes!(Hash, 32, "A 32-byte SHA-512/256 hash.");

impl Hash {
    /// Compute a digest of the passed slice of bytes.
    pub fn digest_bytes(data: &[u8]) -> Hash {
        let mut result = [0u8; 32];
        result[..].copy_from_slice(Sha512Trunc256::digest(&data).as_ref());

        Hash(result)
    }

    /// Compute a digest of the passed slices of bytes.
    pub fn digest_bytes_list(data: &[&[u8]]) -> Hash {
        let mut ctx = Sha512Trunc256::new();
        for datum in data {
            ctx.update(datum);
        }

        let mut result = [0u8; 32];
        result[..].copy_from_slice(ctx.finalize().as_ref());

        Hash(result)
    }

    /// Returns true if the hash is of an empty string.
    pub fn is_empty(&self) -> bool {
        return self == &Hash::empty_hash();
    }

    /// Hash of an empty string.
    pub fn empty_hash() -> Hash {
        // This is SHA-512/256 of an empty string.
        Hash([
            0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28, 0xab, 0x87, 0xc3, 0x62, 0x2c, 0x51,
            0x14, 0x06, 0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9, 0x73, 0x74, 0x98, 0xd0, 0xc0, 0x1e,
            0xce, 0xf0, 0x96, 0x7a,
        ])
    }

    /// Hash truncated to the given number of bytes.
    pub fn truncated(&self, n: usize) -> &[u8] {
        &self.0[..n]
    }
}
