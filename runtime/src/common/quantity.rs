//! An arbitrary precision unsigned integer.
use std::{
    convert::TryFrom,
    fmt,
    num::IntErrorKind,
    ops::{Add, AddAssign, Mul, MulAssign},
};

use num_bigint::BigUint;
use num_traits::{CheckedDiv, CheckedSub, ToPrimitive, Zero};

/// An arbitrary precision unsigned integer.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Quantity(BigUint);

impl Quantity {
    /// Subtracts two numbers, checking for underflow. If underflow happens, `None` is returned.
    #[inline]
    pub fn checked_sub(&self, other: &Quantity) -> Option<Quantity> {
        // NOTE: This does not implemented the num_traits::CheckedSub trait because this forces
        //       one to also implement Sub which we explicitly don't want to do.
        self.0.checked_sub(&other.0).map(Quantity)
    }

    /// Divides two numbers, checking for underflow, overflow and division by zero. If any of that
    /// happens, `None` is returned.
    #[inline]
    pub fn checked_div(&self, other: &Quantity) -> Option<Quantity> {
        // NOTE: This does not implemented the num_traits::CheckedDiv trait because this forces
        //       one to also implement Div which we explicitly don't want to do.
        self.0.checked_div(&other.0).map(Quantity)
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

impl From<u8> for Quantity {
    fn from(v: u8) -> Quantity {
        Quantity(BigUint::from(v))
    }
}

impl From<u16> for Quantity {
    fn from(v: u16) -> Quantity {
        Quantity(BigUint::from(v))
    }
}

impl From<u32> for Quantity {
    fn from(v: u32) -> Quantity {
        Quantity(BigUint::from(v))
    }
}

impl From<u64> for Quantity {
    fn from(v: u64) -> Quantity {
        Quantity(BigUint::from(v))
    }
}

impl From<u128> for Quantity {
    fn from(v: u128) -> Quantity {
        Quantity(BigUint::from(v))
    }
}

impl TryFrom<Quantity> for u64 {
    type Error = IntErrorKind;

    fn try_from(value: Quantity) -> Result<u64, Self::Error> {
        value.0.to_u64().ok_or(IntErrorKind::PosOverflow)
    }
}

impl TryFrom<&Quantity> for u64 {
    type Error = IntErrorKind;

    fn try_from(value: &Quantity) -> Result<u64, Self::Error> {
        value.0.to_u64().ok_or(IntErrorKind::PosOverflow)
    }
}

impl TryFrom<Quantity> for u128 {
    type Error = IntErrorKind;

    fn try_from(value: Quantity) -> Result<u128, Self::Error> {
        value.0.to_u128().ok_or(IntErrorKind::PosOverflow)
    }
}

impl TryFrom<&Quantity> for u128 {
    type Error = IntErrorKind;

    fn try_from(value: &Quantity) -> Result<u128, Self::Error> {
        value.0.to_u128().ok_or(IntErrorKind::PosOverflow)
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

impl AddAssign<Quantity> for Quantity {
    fn add_assign(&mut self, other: Quantity) {
        self.0 += other.0;
    }
}

impl Add<u64> for Quantity {
    type Output = Quantity;

    fn add(mut self, other: u64) -> Quantity {
        self += other;
        self
    }
}

impl AddAssign<u64> for Quantity {
    fn add_assign(&mut self, other: u64) {
        self.0 += other;
    }
}

impl Mul for Quantity {
    type Output = Quantity;

    fn mul(mut self, rhs: Quantity) -> Quantity {
        self *= &rhs;
        self
    }
}

impl<'a> Mul<&'a Quantity> for Quantity {
    type Output = Quantity;

    fn mul(mut self, rhs: &Quantity) -> Quantity {
        self *= rhs;
        self
    }
}

impl<'a> MulAssign<&'a Quantity> for Quantity {
    fn mul_assign(&mut self, rhs: &Quantity) {
        self.0 *= &rhs.0;
    }
}

impl MulAssign<Quantity> for Quantity {
    fn mul_assign(&mut self, rhs: Quantity) {
        self.0 *= rhs.0;
    }
}

impl Mul<u64> for Quantity {
    type Output = Quantity;

    fn mul(mut self, other: u64) -> Quantity {
        self *= other;
        self
    }
}

impl MulAssign<u64> for Quantity {
    fn mul_assign(&mut self, other: u64) {
        self.0 *= other;
    }
}

impl fmt::Display for Quantity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl cbor::Encode for Quantity {
    fn is_empty(&self) -> bool {
        self.0.is_zero()
    }

    fn into_cbor_value(self) -> cbor::Value {
        if self.0.is_zero() {
            cbor::Value::ByteString(vec![])
        } else {
            cbor::Value::ByteString(self.0.to_bytes_be())
        }
    }
}

impl cbor::Decode for Quantity {
    fn try_default() -> Result<Self, cbor::DecodeError> {
        Ok(Default::default())
    }

    fn try_from_cbor_value(value: cbor::Value) -> Result<Self, cbor::DecodeError> {
        match value {
            cbor::Value::ByteString(data) => Ok(Quantity(BigUint::from_bytes_be(&data))),
            _ => Err(cbor::DecodeError::UnexpectedType),
        }
    }
}

#[cfg(test)]
mod test {
    use rustc_hex::ToHex;

    use crate::common::quantity::Quantity;

    #[test]
    fn test_serialization() {
        // NOTE: These should be synced with go/common/quantity/quantity_test.go.
        let cases = vec![
            (0u128, "40"),
            (1, "4101"),
            (10, "410a"),
            (100, "4164"),
            (1000, "4203e8"),
            (1000000, "430f4240"),
            (18446744073709551615, "48ffffffffffffffff"),
        ];

        for tc in cases {
            let q = Quantity::from(tc.0);
            let enc = cbor::to_vec(q.clone());
            assert_eq!(enc.to_hex::<String>(), tc.1, "serialization should match");

            let dec: Quantity = cbor::from_slice(&enc).expect("deserialization should succeed");
            assert_eq!(dec, q, "serialization should round-trip");
        }
    }

    #[test]
    fn test_ops() {
        // Add.
        assert_eq!(
            Quantity::from(1000u32) + Quantity::from(2000u32),
            Quantity::from(3000u32)
        );

        let mut a = Quantity::from(1000u32);
        a += Quantity::from(42u32);
        assert_eq!(a, Quantity::from(1042u32));
        a += &Quantity::from(42u32);
        assert_eq!(a, Quantity::from(1084u32));

        let mut a = Quantity::from(1000u32);
        a += 42;
        assert_eq!(a, Quantity::from(1042u32));

        // Sub.
        let a = Quantity::from(1000u32);
        assert_eq!(
            a.checked_sub(&Quantity::from(42u32)),
            Some(Quantity::from(958u32))
        );
        assert_eq!(a.checked_sub(&Quantity::from(1100u32)), None);

        // Mul.
        assert_eq!(
            Quantity::from(1000u32) * Quantity::from(1000u32),
            Quantity::from(1_000_000u32)
        );

        let mut a = Quantity::from(1000u32);
        a *= Quantity::from(1000u32);
        assert_eq!(a, Quantity::from(1_000_000u32));
        a *= &Quantity::from(1000u32);
        assert_eq!(a, Quantity::from(1_000_000_000u32));

        let mut a = Quantity::from(1000u32);
        a *= 1000;
        assert_eq!(a, Quantity::from(1_000_000u32));

        // Div.
        let a = Quantity::from(1000u32);
        assert_eq!(
            a.checked_div(&Quantity::from(3u32)),
            Some(Quantity::from(333u32))
        );
        assert_eq!(
            a.checked_div(&Quantity::from(1001u32)),
            Some(Quantity::from(0u32))
        );
        assert_eq!(a.checked_div(&Quantity::from(0u32)), None);
    }
}
