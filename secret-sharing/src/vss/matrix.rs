use std::{cmp::max, ops::Add};

use group::{Group, GroupEncoding};

use super::{
    arith::powers,
    polynomial::{BivariatePolynomial, Polynomial},
};

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
    pub fn new(bp: &BivariatePolynomial<G::Scalar>) -> Self {
        let rows = bp.deg_x + 1;
        let cols = bp.deg_y + 1;
        let mut m = Vec::new();
        for bi in bp.b.iter() {
            let mut mi = Vec::new();
            for bij in bi.iter() {
                mi.push(G::generator() * bij) // b_{i,j} * G
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

    /// Verifies coefficients of the polynomial resulting from the evaluation
    /// of the bivariate polynomial with respect to the indeterminate x against
    /// the verification matrix in non-constant time.
    ///
    /// The polynomial
    /// ```text
    /// A(y) = \sum_{j=0}^{deg_y} a_j y^j
    /// ```
    /// where
    /// ```text
    /// a_j = \sum_{i=0}^{deg_x} b_{i,j} x^i
    /// ```
    /// is valid iff the following holds:
    /// ```text
    /// a_j * G = \sum_{i=0}^{deg_x} b_{i,j} x^i * G
    ///         = \sum_{i=0}^{deg_x} x^i * M_{i,j}
    /// ```
    pub fn verify_x(&self, polynomial: &Polynomial<G::Scalar>, x: &G::Scalar) -> bool {
        if polynomial.size() != self.cols {
            return false;
        }

        let xpows = powers(x, self.rows - 1); // [x^i]
        for j in 0..self.cols {
            // Verify if the following difference is the identity element (zero)
            // of the group: a_j * G - \sum_{i=0}^{deg_x} x^i * M_{i,j}.
            let aj = polynomial.coefficient(j).expect("size checked above");
            let mut diff = G::generator() * aj; // a_j * G
            for (i, xpow) in xpows.iter().enumerate() {
                diff -= self.m[i][j] * xpow; // x^i * M_{i,j} = b_{i,j} x^i * G
            }

            if !Into::<bool>::into(diff.is_identity()) {
                return false;
            }
        }

        true
    }

    /// Verifies coefficients of the polynomial resulting from the evaluation
    /// of the bivariate polynomial with respect to the indeterminate y against
    /// the verification matrix in non-constant time.
    ///
    ///
    /// The polynomial
    /// ```text
    /// A(x) = \sum_{i=0}^{deg_x} a_i y^i
    /// ```
    /// where
    /// ```text
    /// a_i = \sum_{j=0}^{deg_y} b_{i,j} y^j
    /// ```
    /// is valid iff the following holds:
    /// ```text
    /// a_i * G = \sum_{j=0}^{deg_y} b_{i,j} y^j * G
    ///         = \sum_{j=0}^{deg_y} y^j * M_{i,j}
    /// ```
    pub fn verify_y(&self, polynomial: &Polynomial<G::Scalar>, y: &G::Scalar) -> bool {
        if polynomial.size() != self.rows {
            return false;
        }

        let ypows = powers(y, self.cols - 1); // [y^j]
        for i in 0..self.rows {
            // Verify if the following difference is the identity element (zero)
            // of the group: a_i * G - \sum_{j=0}^{deg_y} y^j * M_{i,j}.
            let ai = polynomial.coefficient(i).expect("size checked above");
            let mut diff = G::generator() * ai; // a_i * G
            for (j, ypow) in ypows.iter().enumerate() {
                diff -= self.m[i][j] * ypow; // y^j * M_{i,j} = b_{i,j} y^j * G
            }

            if !Into::<bool>::into(diff.is_identity()) {
                return false;
            }
        }

        true
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

impl<G> Add for VerificationMatrix<G>
where
    G: Group + GroupEncoding,
{
    type Output = Self;

    fn add(self, other: Self) -> Self {
        &self + &other
    }
}

impl<G> Add for &VerificationMatrix<G>
where
    G: Group + GroupEncoding,
{
    type Output = VerificationMatrix<G>;

    fn add(self, rhs: Self) -> Self::Output {
        let rows = max(self.rows, rhs.rows);
        let cols = max(self.cols, rhs.cols);
        let mut m = Vec::with_capacity(rows);

        for i in 0..rows {
            let mut mi = Vec::with_capacity(cols);

            for j in 0..cols {
                let a = self.m.get(i).and_then(|mi| mi.get(j));
                let b = rhs.m.get(i).and_then(|mi| mi.get(j));

                let s = match (a, b) {
                    (Some(a), Some(b)) => *a + *b,
                    (Some(a), None) => *a,
                    (None, Some(b)) => *b,
                    (None, None) => G::identity(),
                };

                mi.push(s);
            }

            m.push(mi);
        }

        VerificationMatrix { rows, cols, m }
    }
}

#[cfg(test)]
mod tests {
    use group::Group;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::vss::matrix::VerificationMatrix;

    use super::BivariatePolynomial;

    fn scalars(values: &[i64]) -> Vec<p384::Scalar> {
        values
            .iter()
            .map(|&w| match w.is_negative() {
                false => p384::Scalar::from_u64(w as u64),
                true => p384::Scalar::from_u64(-w as u64).neg(),
            })
            .collect()
    }

    #[test]
    fn test_new() {
        // Two non-zero coefficients (fast).
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut bp = BivariatePolynomial::<p384::Scalar>::zero(2, 3);
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
        let bp: BivariatePolynomial<p384::Scalar> = BivariatePolynomial::random(5, 10, &mut rng);
        let _: VerificationMatrix<p384::ProjectivePoint> = VerificationMatrix::new(&bp);
    }

    #[test]
    fn test_verify_x() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let x2 = p384::Scalar::from_u64(2);

        // Asymmetric bivariate polynomial.
        let bp: BivariatePolynomial<p384::Scalar> = BivariatePolynomial::random(2, 3, &mut rng);
        let p = bp.eval_x(&x2);
        let vm: VerificationMatrix<p384::ProjectivePoint> = VerificationMatrix::new(&bp);
        assert!(vm.verify_x(&p, &x2));
        assert!(!vm.verify_y(&p, &x2)); // Invalid degree.

        // Symmetric bivariate polynomial.
        let bp: BivariatePolynomial<p384::Scalar> = BivariatePolynomial::random(2, 2, &mut rng);
        let p = bp.eval_x(&x2);
        let vm: VerificationMatrix<p384::ProjectivePoint> = VerificationMatrix::new(&bp);
        assert!(vm.verify_x(&p, &x2));
        assert!(!vm.verify_y(&p, &x2)); // Valid degree, but verification failed.
    }

    #[test]
    fn test_verify_y() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let y2 = p384::Scalar::from_u64(2);

        // Asymmetric bivariate polynomial.
        let bp: BivariatePolynomial<p384::Scalar> = BivariatePolynomial::random(2, 3, &mut rng);
        let p = bp.eval_y(&y2);
        let vm: VerificationMatrix<p384::ProjectivePoint> = VerificationMatrix::new(&bp);
        assert!(!vm.verify_x(&p, &y2)); // Invalid degree.
        assert!(vm.verify_y(&p, &y2));

        // Symmetric bivariate polynomial.
        let bp: BivariatePolynomial<p384::Scalar> = BivariatePolynomial::random(2, 2, &mut rng);
        let p = bp.eval_y(&y2);
        let vm: VerificationMatrix<p384::ProjectivePoint> = VerificationMatrix::new(&bp);
        assert!(!vm.verify_x(&p, &y2)); // Valid degree, but verification failed.
        assert!(vm.verify_y(&p, &y2));
    }

    #[test]
    fn test_serialization() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let bp = BivariatePolynomial::<p384::Scalar>::random(2, 3, &mut rng);
        let vm = VerificationMatrix::<p384::ProjectivePoint>::new(&bp);
        let restored = VerificationMatrix::<p384::ProjectivePoint>::from_bytes(vm.to_bytes())
            .expect("deserialization should succeed");

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

    #[test]
    fn test_add() {
        let c1 = vec![scalars(&[1, 2, 3, 4]), scalars(&[5, 6, 7, 8])];
        let c2 = vec![scalars(&[1, 2]), scalars(&[3, 4]), scalars(&[5, 6])];
        let bp1 = BivariatePolynomial::with_coefficients(c1);
        let bp2 = BivariatePolynomial::with_coefficients(c2);
        let m1 = VerificationMatrix::<p384::ProjectivePoint>::new(&bp1);
        let m2 = VerificationMatrix::<p384::ProjectivePoint>::new(&bp2);

        let c = vec![
            scalars(&[1 + 1, 2 + 2, 3, 4]),
            scalars(&[5 + 3, 6 + 4, 7, 8]),
            scalars(&[5, 6, 0, 0]),
        ];
        let bp = BivariatePolynomial::with_coefficients(c);
        let m = VerificationMatrix::<p384::ProjectivePoint>::new(&bp);

        let sum = &m1 + &m2;
        assert_eq!(sum.rows, 3);
        assert_eq!(sum.cols, 4);
        assert_eq!(sum, m);

        let sum = m1 + m2;
        assert_eq!(sum.rows, 3);
        assert_eq!(sum.cols, 4);
        assert_eq!(sum, m);
    }
}
