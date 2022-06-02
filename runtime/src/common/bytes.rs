//! Byte array type helpers.

/// Define a byte array-like type.
///
/// # Examples
///
/// ```rust,ignore
/// impl_bytes!(MyType, 32, "A 32-byte type.");
/// ```
#[macro_export]
macro_rules! impl_bytes {
    ($name:ident, $size:expr, $doc:expr) => {
        #[doc=$doc]
        #[derive(Clone, Copy)]
        pub struct $name(pub [u8; $size]);

        impl $name {
            /// Size of this object in bytes.
            pub const fn len() -> usize {
                $size
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Eq for $name {}

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<::core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                &self.0[..] == &other.0[..]
            }
        }

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
                self.0[..].cmp(&other.0[..])
            }
        }

        impl ::core::hash::Hash for $name {
            fn hash<H>(&self, state: &mut H)
            where
                H: ::core::hash::Hasher,
            {
                state.write(&self.0);
                state.finish();
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name([0; $size])
            }
        }

        impl From<$name> for [u8; $size] {
            fn from(b: $name) -> Self {
                b.0
            }
        }

        impl From<&[u8]> for $name {
            fn from(b: &[u8]) -> $name {
                let mut data = [0; $size];
                data.copy_from_slice(b);
                $name(data)
            }
        }

        impl From<&'static str> for $name {
            fn from(s: &'static str) -> $name {
                let s = s.strip_prefix("0x").unwrap_or(s);

                if s.len() % 2 == 1 {
                    ("0".to_owned() + s).parse().unwrap()
                } else {
                    s.parse().unwrap()
                }
            }
        }

        impl From<Vec<u8>> for $name {
            fn from(v: Vec<u8>) -> $name {
                Self::from(&v[..])
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = ::rustc_hex::FromHexError;

            fn from_str(s: &str) -> Result<$name, ::rustc_hex::FromHexError> {
                use ::rustc_hex::FromHex;

                let a: Vec<u8> = s.from_hex()?;
                if a.len() != $size {
                    return Err(::rustc_hex::FromHexError::InvalidHexLength);
                }

                let mut ret = [0; $size];
                ret.copy_from_slice(&a);
                Ok($name(ret))
            }
        }

        // Formatting.

        impl ::core::fmt::LowerHex for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                for i in &self.0[..] {
                    write!(f, "{:02x}", i)?;
                }
                Ok(())
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::LowerHex::fmt(self, f)
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                for i in &self.0[0..2] {
                    write!(f, "{:02x}", i)?;
                }
                write!(f, "…")?;
                for i in &self.0[$size - 2..$size] {
                    write!(f, "{:02x}", i)?;
                }
                Ok(())
            }
        }

        // Serialization.

        impl $crate::cbor::Encode for $name {
            fn into_cbor_value(self) -> $crate::cbor::Value {
                $crate::cbor::Value::ByteString(self.0.into())
            }
        }

        // Deserialization.

        impl $crate::cbor::Decode for $name {
            fn try_default() -> Result<Self, $crate::cbor::DecodeError> {
                Ok(Default::default())
            }

            fn try_from_cbor_value(
                value: $crate::cbor::Value,
            ) -> Result<Self, $crate::cbor::DecodeError> {
                use ::std::convert::TryInto;

                match value {
                    $crate::cbor::Value::ByteString(data) => Ok(Self(
                        data.try_into()
                            .map_err(|_| $crate::cbor::DecodeError::UnexpectedType)?,
                    )),
                    _ => Err($crate::cbor::DecodeError::UnexpectedType),
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    // Use hash of an empty string as a test key.
    const TEST_KEY_BYTES: [u8; 32] = [
        0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28, 0xab, 0x87, 0xc3, 0x62, 0x2c, 0x51, 0x14,
        0x06, 0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9, 0x73, 0x74, 0x98, 0xd0, 0xc0, 0x1e, 0xce, 0xf0,
        0x96, 0x7a,
    ];

    impl_bytes!(TestKey, 32, "test key");

    #[test]
    fn test_length() {
        assert_eq!(TestKey::len(), 32);
    }

    #[test]
    fn test_cbor() {
        // Serialize.
        let test_key = TestKey(TEST_KEY_BYTES);
        let test_key_vec = cbor::to_vec(test_key);

        // CBOR prepends "X " to the binary value.
        let mut expected_test_key_vec = vec![88, 32];
        expected_test_key_vec.extend_from_slice(&TEST_KEY_BYTES);
        assert_eq!(test_key_vec, expected_test_key_vec);

        // Deserialize.
        let new_test_key: TestKey = cbor::from_slice(&test_key_vec).unwrap();
        assert_eq!(new_test_key, test_key);
    }

    #[test]
    fn test_cbor_null() {
        let test_key: TestKey = cbor::from_slice(&[0xF6]).unwrap();
        assert_eq!(
            test_key,
            "0000000000000000000000000000000000000000000000000000000000000000".into()
        );
    }
}
