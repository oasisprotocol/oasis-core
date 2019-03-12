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
                serializer.serialize_bytes(self.as_ref())
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
                        formatter.write_str("bytes or sequence of u8")
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<$name, A::Error>
                    where
                        A: ::serde::de::SeqAccess<'de>,
                    {
                        let mut array = [0; $size];
                        for i in 0..$size {
                            array[i] = seq
                                .next_element()?
                                .ok_or_else(|| ::serde::de::Error::invalid_length(i, &self))?;
                        }
                        Ok($name(array))
                    }

                    fn visit_bytes<E>(self, data: &[u8]) -> Result<$name, E>
                    where
                        E: ::serde::de::Error,
                    {
                        let mut array = [0; $size];
                        if data.len() != $size {
                            return Err(::serde::de::Error::invalid_length(data.len(), &self));
                        }
                        array[..].copy_from_slice(data);
                        Ok($name(array))
                    }
                }

                Ok(deserializer.deserialize_bytes(BytesVisitor)?)
            }
        }
    };
}
