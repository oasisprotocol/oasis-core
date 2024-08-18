use std::iter::zip;

use group::ff::PrimeField;

use crate::poly::Polynomial;

use super::multiplier::Multiplier;

/// Returns the Lagrange interpolation polynomial for the given set of points.
///
/// The Lagrange polynomial is defined as:
/// ```text
/// L(x) = \sum_{i=0}^n y_i * L_i(x)
/// ```
/// where `L_i(x)` represents the i-th Lagrange basis polynomial.
pub fn lagrange<F: PrimeField>(xs: &[F], ys: &[F]) -> Polynomial<F> {
    let ls = basis_polynomials(xs);
    zip(ls, ys).map(|(li, &yi)| li * yi).sum()
}

/// Returns Lagrange basis polynomials for the given set of x values.
///
/// The i-th Lagrange basis polynomial is defined as:
/// ```text
///     L_i(x) = \prod_{j=0,j≠i}^n (x - x_j) / (x_i - x_j)
/// ```
/// i.e. it holds `L_i(x_i)` = 1 and `L_i(x_j) = 0` for all `j ≠ i`.
fn basis_polynomials<F: PrimeField>(xs: &[F]) -> Vec<Polynomial<F>> {
    let m = multiplier_for_basis_polynomials(xs);
    (0..xs.len()).map(|i| basis_polynomial(xs, i, &m)).collect()
}

/// Returns i-th Lagrange basis polynomial for the given set of x values.
///
/// The i-th Lagrange basis polynomial is defined as:
/// ```text
///     L_i(x) = \prod_{j=0,j≠i}^n (x - x_j) / (x_i - x_j)
/// ```
/// i.e. it holds `L_i(x_i)` = 1 and `L_i(x_j) = 0` for all `j ≠ i`.
fn basis_polynomial<F: PrimeField>(
    xs: &[F],
    i: usize,
    multiplier: &Multiplier<Polynomial<F>>,
) -> Polynomial<F> {
    let mut nom = multiplier
        .get_product(i)
        .unwrap_or(Polynomial::with_coefficients(vec![F::ONE]));
    let mut denom = F::ONE;
    for j in 0..xs.len() {
        if j == i {
            continue;
        }
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
pub fn coefficients<F: PrimeField>(xs: &[F]) -> Vec<F> {
    let m = multiplier_for_coefficients(xs);
    (0..xs.len()).map(|i| coefficient(xs, i, &m)).collect()
}

/// Returns i-th Lagrange coefficient for the given set of x values.
///
/// The i-th Lagrange coefficient is defined as:
/// ```text
///     L_i(0) = \prod_{j=0,j≠i}^n x_j / (x_j - x_i)
/// ```
fn coefficient<F: PrimeField>(xs: &[F], i: usize, multiplier: &Multiplier<F>) -> F {
    let mut nom = multiplier.get_product(i).unwrap_or(F::ONE);
    let mut denom = F::ONE;
    for j in 0..xs.len() {
        if j == i {
            continue;
        }
        denom *= xs[j] - xs[i]; // (x_j - x_i)
    }
    let denom_inv = denom.invert().expect("values should be unique");
    nom *= denom_inv; // L_i(0) = nom / denom

    nom
}

/// Creates a multiplier for the nominators in the Lagrange coefficients.
fn multiplier_for_coefficients<F: PrimeField>(xs: &[F]) -> Multiplier<F> {
    Multiplier::new(xs)
}

/// Creates a multiplier for the nominators in the Lagrange basis polynomials.
fn multiplier_for_basis_polynomials<F: PrimeField>(xs: &[F]) -> Multiplier<Polynomial<F>> {
    let basis: Vec<_> = xs
        .iter()
        .map(|x| Polynomial::with_coefficients(vec![*x, F::ONE.neg()])) // (x_j - x)
        .collect();
    Multiplier::new(&basis)
}

#[cfg(test)]
mod tests {
    extern crate test;

    use self::test::Bencher;

    use std::iter::zip;

    use group::ff::Field;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use super::{
        basis_polynomial, basis_polynomials, coefficient, coefficients, lagrange,
        multiplier_for_basis_polynomials, multiplier_for_coefficients,
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
    fn test_lagrange() {
        // Prepare points (x, 2**x + 1).
        let n = 10;
        let xs: Vec<_> = (1..=n as i64).collect();
        let ys: Vec<_> = (1..=n as u32).map(|x| 1 + 2_i64.pow(x)).collect();

        // Test polynomials of different degrees.
        for size in 1..=n {
            let xs = scalars(&xs[..size]);
            let ys = scalars(&ys[..size]);
            let p = lagrange(&xs, &ys);

            // Verify zeros.
            for (x, y) in zip(xs, ys) {
                assert_eq!(p.eval(&x), y);
            }

            // Verify degree.
            assert_eq!(p.size(), size);
        }
    }

    #[test]
    fn test_basis_polynomial() {
        let vec = [
            scalars(&[1]),
            scalars(&[1, 2, 3]),
            scalars(&(1..=50).collect::<Vec<_>>()),
        ];

        for xs in vec {
            let m = multiplier_for_basis_polynomials(&xs);

            for i in 0..xs.len() {
                let p = basis_polynomial(&xs, i, &m);

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
    fn test_coefficient() {
        let vec = [
            scalars(&[1]),
            scalars(&[1, 2, 3]),
            scalars(&(1..=50).collect::<Vec<_>>()),
        ];

        for xs in vec {
            let sm = multiplier_for_coefficients(&xs);
            let pm = multiplier_for_basis_polynomials(&xs);
            for i in 0..xs.len() {
                let c = coefficient(&xs, i, &sm);
                let p = basis_polynomial(&xs, i, &pm);

                assert_eq!(c, p.eval(&scalar(0)));
            }
        }
    }

    fn bench_lagrange(b: &mut Bencher, n: usize) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let xs = random_scalars(n, &mut rng);
        let ys = random_scalars(n, &mut rng);

        b.iter(|| {
            let _p = lagrange(&xs, &ys);
        });
    }

    fn bench_basis_polynomials(b: &mut Bencher, n: usize) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let xs = random_scalars(n, &mut rng);

        b.iter(|| {
            let _p = basis_polynomials(&xs);
        });
    }

    fn bench_coefficients(b: &mut Bencher, n: usize) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let xs = random_scalars(n, &mut rng);

        b.iter(|| {
            let _p = coefficients(&xs);
        });
    }

    #[bench]
    fn bench_lagrange_01(b: &mut Bencher) {
        bench_lagrange(b, 1)
    }

    #[bench]
    fn bench_lagrange_02(b: &mut Bencher) {
        bench_lagrange(b, 2)
    }

    #[bench]
    fn bench_lagrange_05(b: &mut Bencher) {
        bench_lagrange(b, 5)
    }

    #[bench]
    fn bench_lagrange_10(b: &mut Bencher) {
        bench_lagrange(b, 10)
    }

    #[bench]
    fn bench_lagrange_20(b: &mut Bencher) {
        bench_lagrange(b, 20)
    }

    #[bench]
    fn bench_basis_polynomials_01(b: &mut Bencher) {
        bench_basis_polynomials(b, 1)
    }

    #[bench]
    fn bench_basis_polynomials_02(b: &mut Bencher) {
        bench_basis_polynomials(b, 2)
    }

    #[bench]
    fn bench_basis_polynomials_05(b: &mut Bencher) {
        bench_basis_polynomials(b, 5)
    }

    #[bench]
    fn bench_basis_polynomials_10(b: &mut Bencher) {
        bench_basis_polynomials(b, 10)
    }

    #[bench]
    fn bench_basis_polynomials_20(b: &mut Bencher) {
        bench_basis_polynomials(b, 20)
    }

    #[bench]
    fn bench_coefficients_01(b: &mut Bencher) {
        bench_coefficients(b, 1)
    }

    #[bench]
    fn bench_coefficients_02(b: &mut Bencher) {
        bench_coefficients(b, 2)
    }

    #[bench]
    fn bench_coefficients_05(b: &mut Bencher) {
        bench_coefficients(b, 5)
    }

    #[bench]
    fn bench_coefficients_10(b: &mut Bencher) {
        bench_coefficients(b, 10)
    }

    #[bench]
    fn bench_coefficients_20(b: &mut Bencher) {
        bench_coefficients(b, 20)
    }
}
