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
        #[derive(Clone)]
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

        impl Copy for $name {}

        impl Into<[u8; $size]> for $name {
            fn into(self) -> [u8; $size] {
                self.0
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
                let s = if s.starts_with("0x") { &s[2..] } else { s };

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

        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&base64::encode(&self))
                } else {
                    serializer.serialize_bytes(self.as_ref())
                }
            }
        }

        // Deserialization.

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                struct BytesVisitor;

                impl<'de> ::serde::de::Visitor<'de> for BytesVisitor {
                    type Value = $name;

                    fn expecting(
                        &self,
                        formatter: &mut ::std::fmt::Formatter,
                    ) -> ::std::fmt::Result {
                        formatter.write_str("bytes or string expected")
                    }

                    fn visit_str<E>(self, data: &str) -> Result<$name, E>
                    where
                        E: ::serde::de::Error,
                    {
                        let mut array = [0; $size];
                        let bytes = match base64::decode(data) {
                            Ok(b) => b,
                            Err(err) => return match err {
                                base64::DecodeError::InvalidByte(pos, v) => Err(::serde::de::Error::custom(format!("invalid base64-encoded string: invalid byte '{}' at position {}", v, pos))),
                                base64::DecodeError::InvalidLength => Err(::serde::de::Error::custom(format!("invalid base64-encoded string: invalid length {}", data.len()))),
                                base64::DecodeError::InvalidLastSymbol(pos, v) => Err(::serde::de::Error::custom(format!("invalid base64-encoded string: invalid last symbol '{}' at position {}", v, pos))),
                            },
                        };
                        if bytes.len() != $size {
                            return Err(::serde::de::Error::invalid_length(bytes.len(), &self));
                        }
                        array[..].copy_from_slice(&bytes);

                        Ok($name(array))
                    }

                   fn visit_bytes<E>(self, data: &[u8]) -> Result<$name, E>
                    where
                        E: ::serde::de::Error,
                    {
                        if data.len() != $size {
                            return Err(::serde::de::Error::invalid_length(data.len(), &self));
                        }
                        let mut array = [0; $size];
                        array[..].copy_from_slice(data);

                        Ok($name(array))
                    }
                }

                if deserializer.is_human_readable() {
                    Ok(deserializer.deserialize_string(BytesVisitor)?)
                } else {
                    Ok(deserializer.deserialize_bytes(BytesVisitor)?)
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
    fn test_serde_base64() {
        // Serialize.
        let test_key = TestKey(TEST_KEY_BYTES);
        let test_key_str = serde_json::to_string(&test_key).unwrap();
        assert_eq!(
            test_key_str,
            "\"xnK40e9W7Sirh8NiLFEUBpvdOte4+XN0mNDAHs7wlno=\""
        );

        // Deserialize.
        let new_test_key: TestKey = serde_json::from_str(&test_key_str).unwrap();
        assert_eq!(new_test_key, test_key);
    }

    #[test]
    fn test_serde_cbor() {
        // Serialize.
        let test_key = TestKey(TEST_KEY_BYTES);
        let test_key_vec = serde_cbor::to_vec(&test_key).unwrap();

        // CBOR prepends "X " to the binary value.
        let mut expected_test_key_vec = vec![88, 32];
        expected_test_key_vec.extend_from_slice(&TEST_KEY_BYTES);
        assert_eq!(test_key_vec, expected_test_key_vec);

        // Deserialize.
        let new_test_key: TestKey = serde_cbor::from_slice(&test_key_vec).unwrap();
        assert_eq!(new_test_key, test_key);
    }
}
