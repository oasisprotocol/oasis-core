use sp800_185::KMac;

use crate::crypto::{Secret, StateKey};

/// Domain separation tag for deriving a key-derivation key from a shared secret.
pub const DERIVE_KDK_CUSTOM: &[u8] = b"oasis-core/keymanager/churp: derive key derivation key";
/// Domain separation tag for deriving a state key from a key-derivation key.
pub const DERIVE_STATE_KEY_CUSTOM: &[u8] = b"oasis-core/keymanager/churp: derive state key";

/// Key derivation function which derives key manager keys from a shared secret.
pub struct Kdf;

impl Kdf {
    /// Derives a 256-bit state key from a shared secret established
    /// during a key-establishment scheme and a salt, which represents
    /// context-specific information.
    pub fn state_key(shared_secret: &[u8], salt: &[u8]) -> StateKey {
        // Derive key-derivation key from the shared secret.
        let mut key = Secret::default();
        Self::extract_randomness(shared_secret, salt, DERIVE_KDK_CUSTOM, &mut key.0);

        // Derive state key from the key-derivation key.
        let mut state_key = StateKey::default();
        Self::expand_key(&key.0, salt, DERIVE_STATE_KEY_CUSTOM, &mut state_key.0);

        state_key
    }

    /// Derives secret keying material from a shared secret established during
    /// a key-establishment scheme using KMAC256 as the key-derivation method.
    ///
    /// ```text
    ///     keying_material = KMAC256(salt, shared_secret, length, custom)
    /// ```
    ///
    /// The output produced by this method shall only be used as secret keying
    /// material – such as a symmetric key used for data encryption or message
    /// integrity, a secret initialization vector, or, perhaps, a key-derivation
    /// key that will be used to generate additional keying material.
    ///
    /// For more details, see: NIST SP 800-56Cr2.
    fn extract_randomness(shared_secret: &[u8], salt: &[u8], custom: &[u8], buf: &mut [u8]) {
        let mut kmac = KMac::new_kmac256(salt, custom);
        kmac.update(shared_secret);
        kmac.finalize(buf);
    }

    /// Derives secret keying material from a key-derivation key using KMAC256
    /// as the pseudo-random function.
    ///
    /// ```text
    ///     keying_material = KMAC256(key, salt, length, custom)
    /// ```
    /// The derived keying material may subsequently be segmented into multiple
    /// disjoint (i.e., non-overlapping) keys.
    ///
    /// For more details, see: NIST SP 800-108r1-upd1.
    fn expand_key(key: &[u8], salt: &[u8], custom: &[u8], buf: &mut [u8]) {
        let mut kmac = KMac::new_kmac256(key, custom);
        kmac.update(salt);
        kmac.finalize(buf);
    }
}

#[cfg(test)]
mod tests {
    use rustc_hex::ToHex;

    use super::*;

    const KEY: &[u8] = b"key";
    const SALT: &[u8] = b"salt";
    const CUSTOM: &[u8] = b"custom";
    const SHARED_SECRET: &[u8] = b"shared secret";

    #[test]
    fn test_state_key_consistency() {
        let state_key = Kdf::state_key(SHARED_SECRET, SALT);

        assert_eq!(
            state_key.0.to_hex::<String>(),
            "c325cc26462f0c59849df88868c17ffa97619eb54afed2a22f4d67ce499ab510"
        );
    }

    #[test]
    fn test_extract_randomness_consistency() {
        let mut buf = [0u8; 32];
        Kdf::extract_randomness(SHARED_SECRET, SALT, CUSTOM, &mut buf);

        assert_eq!(
            buf.to_hex::<String>(),
            "999fc0a1248e69a746c95f8b02a5da862093637442f307c68906c0647fad2845"
        );
    }

    #[test]
    fn test_expand_key_consistency() {
        let mut buf = [0u8; 32];
        Kdf::expand_key(KEY, SALT, CUSTOM, &mut buf);

        assert_eq!(
            buf.to_hex::<String>(),
            "c80574bfd7c5a3f5234c2cf7b72ac457204ee6cf9f75c1e15ce3a6d992a11d29"
        );
    }
}
