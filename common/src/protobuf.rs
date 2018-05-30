//! Protocol buffers serialization.
extern crate protobuf as extern_protobuf;

pub use self::extern_protobuf::*;

/// Implement Serde support for given Protocol Buffers message type.
#[macro_export]
macro_rules! impl_serde_for_protobuf {
    ($name:ident) => {
        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                match self.write_to_bytes() {
                    Ok(data) => data.serialize(serializer),
                    Err(_) => Err(::serde::ser::Error::custom("failed for encode protobuf")),
                }
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let buffer: Vec<u8> = ::serde::Deserialize::deserialize(deserializer)?;
                match $crate::protobuf::parse_from_bytes(&buffer) {
                    Ok(value) => Ok(value),
                    Err(_) => Err(::serde::de::Error::custom("failed to decode protbuf")),
                }
            }
        }
    };
}
