//! An arbitrary precision unsigned integer.
use core::cmp::Ordering::{Equal, Greater, Less};
use std::{
    fmt,
    ops::{Add, AddAssign, Sub},
};

use num_bigint::BigUint;
use num_traits::{Num, Zero};
use serde;

/// An arbitrary precision unsigned integer.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Quantity(BigUint);

impl Quantity {
    /// Subtracts two numbers, checking for underflow. If underflow happens, `None` is returned.
    #[inline]
    pub fn checked_sub(&self, other: &Quantity) -> Option<Quantity> {
        // NOTE: This does not implemented the num_traits::CheckedSub trait because this forces
        //       one to also implement Sub which we explicitly don't want to do.
        match self.0.cmp(&other.0) {
            Less => None,
            Equal => Some(Zero::zero()),
            Greater => Some(Quantity(self.0.clone().sub(&other.0))),
        }
    }
}

impl Zero for Quantity {
    fn zero() -> Self {
        Quantity(BigUint::zero())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl From<u64> for Quantity {
    fn from(v: u64) -> Quantity {
        Quantity(BigUint::from(v))
    }
}

impl Add for Quantity {
    type Output = Quantity;

    fn add(mut self, other: Quantity) -> Quantity {
        self += &other;
        self
    }
}

impl<'a> Add<&'a Quantity> for Quantity {
    type Output = Quantity;

    fn add(mut self, other: &Quantity) -> Quantity {
        self += other;
        self
    }
}

impl<'a> AddAssign<&'a Quantity> for Quantity {
    fn add_assign(&mut self, other: &Quantity) {
        self.0 += &other.0;
    }
}

impl serde::Serialize for Quantity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        if is_human_readable {
            serializer.serialize_str(&self.0.to_str_radix(10))
        } else {
            if self.0.is_zero() {
                serializer.serialize_bytes(&[])
            } else {
                let data = self.0.to_bytes_be();
                serializer.serialize_bytes(&data)
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for Quantity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Quantity;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("bytes or string expected")
            }

            fn visit_str<E>(self, data: &str) -> Result<Quantity, E>
            where
                E: serde::de::Error,
            {
                Ok(Quantity(
                    BigUint::from_str_radix(data, 10)
                        .map_err(|e| serde::de::Error::custom(format!("{}", e)))?,
                ))
            }

            fn visit_bytes<E>(self, data: &[u8]) -> Result<Quantity, E>
            where
                E: serde::de::Error,
            {
                Ok(Quantity(BigUint::from_bytes_be(data)))
            }
        }

        if deserializer.is_human_readable() {
            Ok(deserializer.deserialize_string(BytesVisitor)?)
        } else {
            Ok(deserializer.deserialize_bytes(BytesVisitor)?)
        }
    }
}

#[cfg(test)]
mod test {
    use rustc_hex::ToHex;

    use crate::common::{cbor, quantity::Quantity};

    #[test]
    fn test_serialization() {
        // NOTE: These should be synced with go/common/quantity/quantity_test.go.
        let cases = vec![
            (0, "40"),
            (1, "4101"),
            (10, "410a"),
            (100, "4164"),
            (1000, "4203e8"),
            (1000000, "430f4240"),
            (18446744073709551615, "48ffffffffffffffff"),
        ];

        for tc in cases {
            let q = Quantity::from(tc.0);
            let enc = cbor::to_vec(&q);
            assert_eq!(enc.to_hex::<String>(), tc.1, "serialization should match");

            let dec: Quantity = cbor::from_slice(&enc).expect("deserialization should succeed");
            assert_eq!(dec, q, "serialization should round-trip");
        }
    }
}
