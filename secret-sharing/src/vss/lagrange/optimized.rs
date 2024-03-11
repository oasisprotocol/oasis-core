use std::iter::zip;

use group::ff::PrimeField;

use crate::vss::polynomial::Polynomial;

use super::multiplier::Multiplier;

/// Returns the Lagrange interpolation polynomial for the given set of points.
///
/// The Lagrange polynomial is defined as:
/// ```text
/// L(x) = \sum_{i=0}^n y_i * L_i(x)
/// ```
/// where `L_i(x)` represents the i-th Lagrange basis polynomial.
pub fn lagrange<Fp>(xs: &[Fp], ys: &[Fp]) -> Polynomial<Fp>
where
    Fp: PrimeField,
{
    let m = multiplier(xs);
    let ls = (0..xs.len())
        .map(|i| basis_polynomial(i, xs, &m))
        .collect::<Vec<_>>();

    zip(ls, ys).map(|(li, &yi)| li * yi).sum()
}

/// Returns i-th Lagrange basis polynomials for the given set of x values.
///
/// The i-th Lagrange basis polynomial is defined as:
/// ```text
/// L_i(x) = \prod_{j=0,j≠i}^n (x - x_j) / (x_i - x_j)
/// ```
/// i.e. it holds `L_i(x_i)` = 1 and `L_i(x_j) = 0` for all `j ≠ i`.
fn basis_polynomial<Fp>(
    i: usize,
    xs: &[Fp],
    multiplier: &Multiplier<Polynomial<Fp>>,
) -> Polynomial<Fp>
where
    Fp: PrimeField,
{
    let mut nom = multiplier.get_product(i);
    let mut denom = Fp::ONE;
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

/// Creates a multiplier for the nominators in the Lagrange basis polynomials.
fn multiplier<Fp>(xs: &[Fp]) -> Multiplier<Polynomial<Fp>>
where
    Fp: PrimeField,
{
    let basis: Vec<_> = xs
        .iter()
        .map(|x| Polynomial::with_coefficients(vec![*x, Fp::ONE.neg()])) // (x_j - x)
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

    use super::{basis_polynomial, lagrange, multiplier};

    fn scalar(value: i64) -> p384::Scalar {
        scalars(&vec![value])[0]
    }

    fn scalars(values: &[i64]) -> Vec<p384::Scalar> {
        values
            .iter()
            .map(|&w| match w.is_negative() {
                false => p384::Scalar::from_u64(w as u64),
                true => p384::Scalar::from_u64(-w as u64).neg(),
            })
            .collect()
    }

    fn random_scalars(n: usize, mut rng: &mut impl RngCore) -> Vec<p384::Scalar> {
        (0..n).map(|_| p384::Scalar::random(&mut rng)).collect()
    }

    #[test]
    fn test_lagrange() {
        let xs = scalars(&[1, 2, 3]);
        let ys = scalars(&[2, 4, 8]);
        let p = lagrange(&xs, &ys);

        // Verify zeros.
        for (x, y) in zip(xs, ys) {
            assert_eq!(p.eval(&x), y);
        }

        // Verify degree.
        assert_eq!(p.highest_degree(), 2);
    }

    #[test]
    fn test_basis_polynomial() {
        let xs = scalars(&[1, 2, 3]);
        let m = multiplier(&xs);

        for i in 0..xs.len() {
            let p = basis_polynomial(i, &xs, &m);

            // Verify points.
            for (j, x) in xs.iter().enumerate() {
                if j == i {
                    assert_eq!(p.eval(x), scalar(1)); // L_i(x_i) = 1
                } else {
                    assert_eq!(p.eval(x), scalar(0)); // L_i(x_j) = 0
                }
            }

            // Verify degree.
            assert_eq!(p.highest_degree(), 2);
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

    #[bench]
    fn bench_lagrange_1(b: &mut Bencher) {
        bench_lagrange(b, 1)
    }

    #[bench]
    fn bench_lagrange_2(b: &mut Bencher) {
        bench_lagrange(b, 2)
    }

    #[bench]
    fn bench_lagrange_5(b: &mut Bencher) {
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
}
