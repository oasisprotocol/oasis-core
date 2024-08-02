// Lagrange Polynomials interpolation / reconstruction
use std::iter::zip;

use group::ff::PrimeField;

use crate::poly::Polynomial;

/// Returns the Lagrange interpolation polynomial for the given set of points.
///
/// The Lagrange polynomial is defined as:
/// ```text
///     L(x) = \sum_{i=0}^n y_i * L_i(x)
/// ```
/// where `L_i(x)` represents the i-th Lagrange basis polynomial.
pub fn lagrange_naive<F: PrimeField>(xs: &[F], ys: &[F]) -> Polynomial<F> {
    let ls = basis_polynomials_naive(xs);
    zip(ls, ys).map(|(li, &yi)| li * yi).sum()
}

/// Returns Lagrange basis polynomials for the given set of x values.
///
/// The i-th Lagrange basis polynomial is defined as:
/// ```text
///     L_i(x) = \prod_{j=0,j≠i}^n (x - x_j) / (x_i - x_j)
/// ```
/// i.e. it holds `L_i(x_i)` = 1 and `L_i(x_j) = 0` for all `j ≠ i`.
fn basis_polynomials_naive<F: PrimeField>(xs: &[F]) -> Vec<Polynomial<F>> {
    (0..xs.len())
        .map(|i| basis_polynomial_naive(xs, i))
        .collect()
}

/// Returns i-th Lagrange basis polynomial for the given set of x values.
///
/// The i-th Lagrange basis polynomial is defined as:
/// ```text
///     L_i(x) = \prod_{j=0,j≠i}^n (x - x_j) / (x_i - x_j)
/// ```
/// i.e. it holds `L_i(x_i)` = 1 and `L_i(x_j) = 0` for all `j ≠ i`.
fn basis_polynomial_naive<F: PrimeField>(xs: &[F], i: usize) -> Polynomial<F> {
    let mut nom = Polynomial::with_coefficients(vec![F::ONE]);
    let mut denom = F::ONE;
    for j in 0..xs.len() {
        if j == i {
            continue;
        }
        nom *= Polynomial::with_coefficients(vec![xs[j], F::ONE.neg()]); // (x_j - x)
        denom *= xs[j] - xs[i]; // (x_j - x_i)
    }
    let denom_inv = denom.invert().expect("values should be unique");
    nom *= denom_inv; // L_i(x) = nom / denom

    nom
}

/// Returns Lagrange coefficients for the given set of x values.
///
/// The i-th Lagrange coefficient is defined as:
/// ```text
///     L_i(0) = \prod_{j=0,j≠i}^n x_j / (x_j - x_i)
/// ```
pub fn coefficients_naive<F: PrimeField>(xs: &[F]) -> Vec<F> {
    (0..xs.len()).map(|i| coefficient_naive(xs, i)).collect()
}

/// Returns i-th Lagrange coefficient for the given set of x values.
///
/// The i-th Lagrange coefficient is defined as:
/// ```text
///     L_i(0) = \prod_{j=0,j≠i}^n x_j / (x_j - x_i)
/// ```
fn coefficient_naive<F: PrimeField>(xs: &[F], i: usize) -> F {
    let mut nom = F::ONE;
    let mut denom = F::ONE;
    for j in 0..xs.len() {
        if j == i {
            continue;
        }
        nom *= xs[j]; // x_j
        denom *= xs[j] - xs[i]; // (x_j - x_i)
    }
    let denom_inv = denom.invert().expect("values should be unique");
    nom *= denom_inv; // L_i(0) = nom / denom

    nom
}

#[cfg(test)]
mod tests {
    extern crate test;

    use self::test::Bencher;

    use std::iter::zip;

    use group::ff::Field;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use super::{
        basis_polynomial_naive, basis_polynomials_naive, coefficient_naive, coefficients_naive,
        lagrange_naive,
    };

    type PrimeField = p384::Scalar;

    fn scalar(value: i64) -> PrimeField {
        scalars(&vec![value])[0]
    }

    fn scalars(values: &[i64]) -> Vec<PrimeField> {
        values
            .iter()
            .map(|&w| match w.is_negative() {
                false => PrimeField::from_u64(w as u64),
                true => PrimeField::from_u64(-w as u64).neg(),
            })
            .collect()
    }

    fn random_scalars(n: usize, mut rng: &mut impl RngCore) -> Vec<PrimeField> {
        (0..n).map(|_| PrimeField::random(&mut rng)).collect()
    }

    #[test]
    fn test_lagrange_naive() {
        // Prepare points (x, 2**x + 1).
        let n = 10;
        let xs: Vec<_> = (1..=n as i64).collect();
        let ys: Vec<_> = (1..=n as u32).map(|x| 1 + 2_i64.pow(x)).collect();

        // Test polynomials of different degrees.
        for size in 1..=n {
            let xs = scalars(&xs[..size]);
            let ys = scalars(&ys[..size]);
            let p = lagrange_naive(&xs, &ys);

            // Verify zeros.
            for (x, y) in zip(xs, ys) {
                assert_eq!(p.eval(&x), y);
            }

            // Verify degree.
            assert_eq!(p.size(), size);
        }
    }

    #[test]
    fn test_basis_polynomial_naive() {
        let vec = [
            scalars(&[1]),
            scalars(&[1, 2, 3]),
            scalars(&(1..=50).collect::<Vec<_>>()),
        ];

        for xs in vec {
            for i in 0..xs.len() {
                let p = basis_polynomial_naive(&xs, i);

                // Verify points.
                for (j, x) in xs.iter().enumerate() {
                    if j == i {
                        assert_eq!(p.eval(x), scalar(1)); // L_i(x_i) = 1
                    } else {
                        assert_eq!(p.eval(x), scalar(0)); // L_i(x_j) = 0
                    }
                }

                // Verify degree.
                assert_eq!(p.size(), xs.len());
            }
        }
    }

    #[test]
    fn test_coefficient_naive() {
        let vec = [
            scalars(&[1]),
            scalars(&[1, 2, 3]),
            scalars(&(1..=50).collect::<Vec<_>>()),
        ];

        for xs in vec {
            for i in 0..xs.len() {
                let c = coefficient_naive(&xs, i);
                let p = basis_polynomial_naive(&xs, i);

                assert_eq!(c, p.eval(&scalar(0)));
            }
        }
    }

    fn bench_lagrange_naive(b: &mut Bencher, n: usize) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let xs = random_scalars(n, &mut rng);
        let ys = random_scalars(n, &mut rng);

        b.iter(|| {
            let _p = lagrange_naive(&xs, &ys);
        });
    }

    fn bench_basis_polynomials_naive(b: &mut Bencher, n: usize) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let xs = random_scalars(n, &mut rng);

        b.iter(|| {
            let _p = basis_polynomials_naive(&xs);
        });
    }

    fn bench_coefficients_naive(b: &mut Bencher, n: usize) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let xs = random_scalars(n, &mut rng);

        b.iter(|| {
            let _p = coefficients_naive(&xs);
        });
    }

    #[bench]
    fn bench_lagrange_naive_01(b: &mut Bencher) {
        bench_lagrange_naive(b, 1)
    }

    #[bench]
    fn bench_lagrange_naive_02(b: &mut Bencher) {
        bench_lagrange_naive(b, 2)
    }

    #[bench]
    fn bench_lagrange_naive_05(b: &mut Bencher) {
        bench_lagrange_naive(b, 5)
    }

    #[bench]
    fn bench_lagrange_naive_10(b: &mut Bencher) {
        bench_lagrange_naive(b, 10)
    }

    #[bench]
    fn bench_lagrange_naive_20(b: &mut Bencher) {
        bench_lagrange_naive(b, 20)
    }

    #[bench]
    fn bench_basis_polynomials_naive_01(b: &mut Bencher) {
        bench_basis_polynomials_naive(b, 1)
    }

    #[bench]
    fn bench_basis_polynomials_naive_02(b: &mut Bencher) {
        bench_basis_polynomials_naive(b, 2)
    }

    #[bench]
    fn bench_basis_polynomials_naive_05(b: &mut Bencher) {
        bench_basis_polynomials_naive(b, 5)
    }

    #[bench]
    fn bench_basis_polynomials_naive_10(b: &mut Bencher) {
        bench_basis_polynomials_naive(b, 10)
    }

    #[bench]
    fn bench_basis_polynomials_naive_20(b: &mut Bencher) {
        bench_basis_polynomials_naive(b, 20)
    }

    #[bench]
    fn bench_coefficients_naive_01(b: &mut Bencher) {
        bench_coefficients_naive(b, 1)
    }

    #[bench]
    fn bench_coefficients_naive_02(b: &mut Bencher) {
        bench_coefficients_naive(b, 2)
    }

    #[bench]
    fn bench_coefficients_naive_05(b: &mut Bencher) {
        bench_coefficients_naive(b, 5)
    }

    #[bench]
    fn bench_coefficients_naive_10(b: &mut Bencher) {
        bench_coefficients_naive(b, 10)
    }

    #[bench]
    fn bench_coefficients_naive_20(b: &mut Bencher) {
        bench_coefficients_naive(b, 20)
    }
}
