use group::{ff::PrimeField, Group, GroupEncoding};

use super::polynomial::BivariatePolynomial;

/// Verification matrix over a cryptographic group.
///
/// The verification matrix is computed as the element-wise scalar product
/// of a matrix `b` representing the coefficients of a bivariate polynomial
/// and a group generator `G`.
///
/// ```text
/// M = [b_{i,j} * G]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationMatrix<G>
where
    G: Group + GroupEncoding,
{
    /// The number of rows in the verification matrix, determined by
    /// the degree of the bivariate polynomial in the x variable from
    /// which the matrix was constructed.
    pub rows: usize,
    /// The number of columns in the verification matrix, determined by
    /// the degree of the bivariate polynomial in the y variable from
    /// which the matrix was constructed.
    pub cols: usize,
    /// The verification matrix elements, where `m[i][j]` represents
    /// the element `b_{i,j} * G`.
    pub m: Vec<Vec<G>>,
}

impl<G> VerificationMatrix<G>
where
    G: Group + GroupEncoding,
{
    /// Constructs a new verification matrix from a given bivariate polynomial.
    pub fn new<Fp>(bp: &BivariatePolynomial<Fp>) -> Self
    where
        Fp: PrimeField,
        G: Group<Scalar = Fp> + GroupEncoding,
    {
        let rows = bp.deg_x + 1;
        let cols = bp.deg_y + 1;
        let mut m = Vec::new();
        for ai in bp.b.iter() {
            let mut mi = Vec::new();
            for aij in ai.iter() {
                mi.push(G::generator() * aij)
            }
            m.push(mi)
        }

        Self { rows, cols, m }
    }

    /// Returns true if and only if `m_{0,0}` is the identity element
    /// of the group.
    pub fn is_zero_hole(&self) -> bool {
        self.m[0][0] == G::identity()
    }

    /// Returns the byte representation of the verification matrix.
    pub fn to_bytes(&self) -> Vec<u8> {
        let cap = Self::byte_size(self.rows, self.cols);
        let mut bytes = Vec::with_capacity(cap);
        let deg_x = (self.rows - 1) as u8;
        let deg_y = (self.cols - 1) as u8;
        bytes.extend([deg_x, deg_y].iter());
        for mi in &self.m {
            for mij in mi {
                bytes.extend_from_slice(mij.to_bytes().as_ref());
            }
        }

        bytes
    }

    /// Attempts to create a verification matrix from its byte representation.
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }

        let deg_x = bytes[0] as usize;
        let deg_y = bytes[1] as usize;
        let rows = deg_x + 1;
        let cols = deg_y + 1;

        if bytes.len() != Self::byte_size(rows, cols) {
            return None;
        }

        let mut bytes = &bytes[2..];
        let mut m = Vec::with_capacity(rows);
        for _ in 0..=deg_x {
            let mut mi = Vec::with_capacity(cols);
            for _ in 0..=deg_y {
                let mut repr: G::Repr = Default::default();
                let slice = &mut repr.as_mut()[..];
                let (bij, rest) = bytes.split_at(slice.len());
                slice.copy_from_slice(bij);
                bytes = rest;

                let mij = match G::from_bytes(&repr).into() {
                    None => return None,
                    Some(mij) => mij,
                };

                mi.push(mij);
            }
            m.push(mi);
        }

        Some(Self { cols, rows, m })
    }

    /// Returns the size of the byte representation of a matrix element.
    pub fn element_byte_size() -> usize {
        // Is there a better way?
        G::Repr::default().as_ref().len()
    }

    /// Returns the size of the byte representation of the verification matrix.
    pub fn byte_size(rows: usize, cols: usize) -> usize {
        2 + rows * cols * Self::element_byte_size()
    }
}

#[cfg(test)]
mod tests {
    use group::Group;
    use rand_core::OsRng;

    use crate::vss::matrix::VerificationMatrix;

    use super::BivariatePolynomial;

    #[test]
    fn test_new() {
        // Two non-zero coefficients (fast).
        let mut bp: BivariatePolynomial<p384::Scalar> = BivariatePolynomial::zero(2, 3);
        bp.set_coefficient(p384::Scalar::ONE, 0, 0);
        bp.set_coefficient(p384::Scalar::ONE.double(), 2, 2);

        let vm: VerificationMatrix<p384::ProjectivePoint> = VerificationMatrix::new(&bp);
        assert_eq!(vm.m.len(), 3);
        for (i, mi) in vm.m.iter().enumerate() {
            assert_eq!(mi.len(), 4);
            for (j, mij) in mi.iter().enumerate() {
                match (i, j) {
                    (0, 0) => assert_eq!(mij, &p384::ProjectivePoint::GENERATOR),
                    (2, 2) => assert_eq!(mij, &p384::ProjectivePoint::GENERATOR.double()),
                    _ => assert_eq!(mij, &p384::ProjectivePoint::IDENTITY),
                }
            }
        }

        // Random bivariate polynomial (slow).
        let bp: BivariatePolynomial<p384::Scalar> = BivariatePolynomial::random(5, 10, &mut OsRng);
        let _: VerificationMatrix<p384::ProjectivePoint> = VerificationMatrix::new(&bp);
    }

    #[test]
    fn test_serialization() {
        let bp: BivariatePolynomial<p384::Scalar> = BivariatePolynomial::random(2, 3, &mut OsRng);
        let vm: VerificationMatrix<p384::ProjectivePoint> = VerificationMatrix::new(&bp);
        let restored: VerificationMatrix<p384::ProjectivePoint> =
            VerificationMatrix::from_bytes(vm.to_bytes()).expect("deserialization should succeed");

        assert_eq!(vm, restored);
    }

    #[test]
    fn test_element_byte_size() {
        let size = VerificationMatrix::<p384::ProjectivePoint>::element_byte_size();
        assert_eq!(size, 49);
    }

    #[test]
    fn test_byte_size() {
        let size = VerificationMatrix::<p384::ProjectivePoint>::byte_size(2, 3);
        assert_eq!(size, 2 + 2 * 3 * 49);
    }
}
