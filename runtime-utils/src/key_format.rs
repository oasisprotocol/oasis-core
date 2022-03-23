use std::{convert::TryInto, mem::size_of};

use impl_trait_for_tuples::impl_for_tuples;

/// Size of the KeyFormat prefix.
const KEY_FORMAT_PREFIX_SIZE: usize = size_of::<u8>();

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
        let mut v = Vec::with_capacity(KEY_FORMAT_PREFIX_SIZE + Self::size());
        v.push(Self::prefix());

        if count == 0 {
            return v;
        }

        let mut atoms = Vec::new();
        self.encode_atoms(&mut atoms);
        for (included, mut atom) in atoms.into_iter().enumerate() {
            if included >= count {
                break;
            }
            v.append(&mut atom);
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
        assert!(!data.is_empty(), "key format: malformed input (empty data)");
        if data[0] != Self::prefix() {
            return None;
        }
        assert!(
            data.len() >= Self::size() + KEY_FORMAT_PREFIX_SIZE,
            "key format: malformed input"
        );

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

impl KeyFormatAtom for u8 {
    fn size() -> usize {
        1
    }

    fn encode_atom(self) -> Vec<u8> {
        vec![self]
    }

    fn decode_atom(data: &[u8]) -> Self
    where
        Self: Sized,
    {
        assert!(!data.is_empty(), "key_format: malformed: u8 input");
        data[0]
    }
}

impl KeyFormatAtom for () {
    fn size() -> usize {
        0
    }

    fn encode_atom(self) -> Vec<u8> {
        Vec::new()
    }

    fn decode_atom(_: &[u8]) {}
}

#[impl_for_tuples(2, 10)]
impl KeyFormatAtom for Tuple {
    fn size() -> usize {
        for_tuples!( #( Tuple::size() )+* );
    }

    fn encode_atom(self) -> Vec<u8> {
        let mut atoms: Vec<Vec<u8>> = [for_tuples!( #( self.Tuple.encode_atom() ),* )].to_vec();

        atoms.into_iter().flatten().collect()
    }

    fn decode_atom(data: &[u8]) -> for_tuples!( ( #( Tuple ),* ) ) {
        assert!(
            data.len() >= Self::size(),
            "key format atom: malformed input"
        );

        let mut sizes: Vec<usize> = [for_tuples!( #( Tuple::size() ),* )].to_vec();
        sizes.reverse();
        let mut data = data.to_vec();

        /*
            (
                {
                    let x = T1::decode_atom(data.drain(0..T1::size()));
                    x
                },
                {
                    let x = T2::decode_atom(data.drain(0..T2::size()));
                    x
                }
                ...
            )
        */
        for_tuples!(
            (
                #(
                    {
                        let x = Tuple::decode_atom(data.drain(0..sizes.pop().unwrap()).as_slice());
                        x
                    }
                ),*
            )
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
        #[derive(Debug, Default, PartialEq, Eq, Clone)]
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
            b'T'
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

    #[test]
    fn test_key_format_atom() {
        key_format!(TestKeyFormat, 0x01, (u8, u64, u8, u64, u64));

        let key = TestKeyFormat((1, 2, 3, 4, 5));
        let enc = key.clone().encode();
        let dec = TestKeyFormat::decode(&enc);

        assert_eq!(dec, Some(key),)
    }
}
