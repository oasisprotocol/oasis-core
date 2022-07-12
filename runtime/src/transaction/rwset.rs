//! Read/write set.

/// A coarsened key prefix that represents any key that starts with
/// this prefix.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
#[cbor(transparent)]
pub struct CoarsenedKey(pub Vec<u8>);

impl AsRef<[u8]> for CoarsenedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<CoarsenedKey> for Vec<u8> {
    fn from(val: CoarsenedKey) -> Self {
        val.0
    }
}

impl From<Vec<u8>> for CoarsenedKey {
    fn from(v: Vec<u8>) -> CoarsenedKey {
        CoarsenedKey(v)
    }
}

/// A set of coarsened keys.
pub type CoarsenedSet = Vec<CoarsenedKey>;

/// A read/write set.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct ReadWriteSet {
    /// Size of the key prefixes (in bytes) used for coarsening the keys.
    pub granularity: u16,
    /// The read set.
    pub read_set: CoarsenedSet,
    /// The write set.
    pub write_set: CoarsenedSet,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_serialization() {
        let rw_set = ReadWriteSet {
            granularity: 3,
            read_set: vec![b"foo".to_vec().into(), b"bar".to_vec().into()],
            write_set: vec![b"moo".to_vec().into()],
        };

        let enc = cbor::to_vec(rw_set.clone());

        let dec_rw_set: ReadWriteSet = cbor::from_slice(&enc).unwrap();
        assert_eq!(rw_set, dec_rw_set, "serialization should round-trip");
    }
}
