use std::convert::TryInto;

/// A key formatting helper trait to be used together with key-value
/// backends for constructing keys.
pub trait KeyFormat {
    /// The prefix that identifies the key format.
    fn prefix() -> u8;

    /// The minimum size of the encoded key.
    fn size() -> usize;

    /// Encode the given key format into a set of atoms.
    fn encode_atoms(self, atoms: &mut Vec<Vec<u8>>);

    /// Decode the given key format from data (without prefix).
    ///
    /// The caller must ensure that the size of the passed data is at
    /// least the minimum size returned by `size`.
    fn decode_atoms(data: &[u8]) -> Self
    where
        Self: Sized;

    /// Encode the first few atoms in the key format.
    ///
    /// This method can be used to construct key prefixes for iteration.
    /// Specifying a zero count will only generate the prefix.
    fn encode_partial(self, count: usize) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut v = Vec::with_capacity(1 + Self::size());
        v.push(Self::prefix());

        if count == 0 {
            return v;
        }

        let mut atoms = Vec::new();
        let mut included = 0;
        self.encode_atoms(&mut atoms);
        for mut atom in atoms {
            if included >= count {
                break;
            }
            v.append(&mut atom);
            included += 1;
        }

        v
    }

    /// Encode the given key format.
    fn encode(self) -> Vec<u8>
    where
        Self: Sized,
    {
        self.encode_partial(usize::max_value())
    }

    /// Decode the given key format from data.
    ///
    /// The method may return `None` in case the key is of a different
    /// type as indicated by the prefix byte.
    fn decode(data: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        if data[0] != Self::prefix() {
            return None;
        }
        if data.len() < 1 + Self::size() {
            panic!("key format: malformed input");
        }

        Some(Self::decode_atoms(&data[1..]))
    }
}

/// Part of the KeyFormat to be used with key-value backends for constructing keys.
pub trait KeyFormatAtom {
    fn size() -> usize;

    fn encode_atom(self) -> Vec<u8>;

    fn decode_atom(data: &[u8]) -> Self
    where
        Self: Sized;
}

impl KeyFormatAtom for u64 {
    fn size() -> usize {
        8
    }

    fn encode_atom(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn decode_atom(data: &[u8]) -> Self
    where
        Self: Sized,
    {
        u64::from_be_bytes(data.try_into().expect("key_format: malformed u64 input"))
    }
}

impl KeyFormatAtom for () {
    fn size() -> usize {
        0
    }

    fn encode_atom(self) -> Vec<u8> {
        Vec::new()
    }

    fn decode_atom(_: &[u8]) -> () {
        ()
    }
}

impl<T1, T2> KeyFormatAtom for (T1, T2)
where
    T1: KeyFormatAtom,
    T2: KeyFormatAtom,
{
    fn size() -> usize {
        T1::size() + T2::size()
    }

    fn encode_atom(self) -> Vec<u8> {
        let mut a = self.0.encode_atom();
        let mut b = self.1.encode_atom();
        a.append(&mut b);
        a
    }

    fn decode_atom(data: &[u8]) -> (T1, T2) {
        if data.len() < Self::size() {
            panic!("key format atom: malformed input");
        }

        (
            T1::decode_atom(&data[0..T1::size()]),
            T2::decode_atom(&data[T2::size()..]),
        )
    }
}

// TODO: probably could generalize this for N sized tuples using macros.
impl<T1, T2, T3> KeyFormatAtom for (T1, T2, T3)
where
    T1: KeyFormatAtom,
    T2: KeyFormatAtom,
    T3: KeyFormatAtom,
{
    fn size() -> usize {
        T1::size() + T2::size() + T3::size()
    }

    fn encode_atom(self) -> Vec<u8> {
        let mut a = self.0.encode_atom();
        let mut b = self.1.encode_atom();
        let mut c = self.2.encode_atom();
        a.append(&mut b);
        a.append(&mut c);
        a
    }

    fn decode_atom(data: &[u8]) -> (T1, T2, T3) {
        if data.len() < Self::size() {
            panic!("key format atom: malformed input");
        }

        (
            T1::decode_atom(&data[0..T1::size()]),
            T2::decode_atom(&data[T2::size()..T3::size()]),
            T3::decode_atom(&data[T3::size()..]),
        )
    }
}

/// Define a KeyFormat from KeyFromatAtom and a prefix.
///
/// # Examples
///
/// ```rust,ignore
/// key_format!(NewKeyFormatName, 0x01, InnerType);
/// ```
#[macro_export]
macro_rules! key_format {
    ($name:ident, $prefix:expr, $inner:ty) => {
        #[derive(Debug, Default)]
        struct $name($inner);

        impl KeyFormat for $name {
            fn prefix() -> u8 {
                $prefix
            }

            fn size() -> usize {
                <$inner>::size()
            }

            fn encode_atoms(self, atoms: &mut Vec<Vec<u8>>) {
                atoms.push(self.0.encode_atom());
            }

            fn decode_atoms(data: &[u8]) -> Self {
                Self(<$inner>::decode_atom(data))
            }
        }
    };
}

#[cfg(test)]
mod test {
    use rustc_hex::ToHex;

    use crate::common::crypto::hash::Hash;

    use super::*;

    #[derive(Debug, PartialEq)]
    struct Test1KeyFormat {
        h: Hash,
    }

    impl KeyFormat for Test1KeyFormat {
        fn prefix() -> u8 {
            'T' as u8
        }

        fn size() -> usize {
            32
        }

        fn encode_atoms(self, atoms: &mut Vec<Vec<u8>>) {
            atoms.push(self.h.as_ref().to_vec());
        }

        fn decode_atoms(data: &[u8]) -> Self {
            Self { h: data.into() }
        }
    }

    #[test]
    fn test_key_format() {
        let mut enc = Test1KeyFormat {
            h: Hash::empty_hash(),
        }
        .encode();
        assert_eq!(
            enc.to_hex::<String>(),
            "54c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
        );

        let dec = Test1KeyFormat::decode(&enc);
        assert_eq!(
            dec,
            Some(Test1KeyFormat {
                h: Hash::empty_hash()
            })
        );

        // Clear type.
        enc[0] = 0x00;
        let dec = Test1KeyFormat::decode(&enc);
        assert_eq!(dec, None);

        // Partial encoding.
        let enc = Test1KeyFormat {
            h: Hash::empty_hash(),
        }
        .encode_partial(0);
        assert_eq!(enc.to_hex::<String>(), "54");
    }
}
