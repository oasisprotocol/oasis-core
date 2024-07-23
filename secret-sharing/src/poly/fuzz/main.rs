use group::ff::PrimeField;
use honggfuzz::fuzz;
use rand::{rngs::StdRng, Rng, SeedableRng};

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            fuzz_bivariate_polynomial_random(data);
            fuzz_bivariate_polynomial_from_seed(data);
            fuzz_bivariate_polynomial_from_bytes(data);
        });
    }
}

fn fuzz_bivariate_polynomial_random(data: &[u8]) {
    BivariatePolynomial::<p384::Scalar>::from_bytes(data.to_vec());
}

fn fuzz_bivariate_polynomial_from_seed(data: &[u8]) {
    if data.len() < 32 {
        return;
    }

    let bp = random_bivariate_polynomial(data);
    let restored = BivariatePolynomial::<p384::Scalar>::from_bytes(bp.to_bytes())
        .expect("deserialization should succeed");
    assert!(bp == restored)
}

fn fuzz_bivariate_polynomial_from_bytes(data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let deg_x = data[0] % 5;
    let deg_y = data[1] % 5;
    let len = BivariatePolynomial::<p384::Scalar>::byte_size(deg_x as usize, deg_y as usize);
    let size = BivariatePolynomial::<p384::Scalar>::coefficient_byte_size();

    if data.len() < len {
        return;
    }

    let mut bytes = data[..len].to_vec();
    bytes[0] = deg_x;
    bytes[1] = deg_y;

    // Make sure all values are smaller that the modulus.
    for i in (2..len).step_by(size) {
        bytes[i] = 0;
    }

    BivariatePolynomial::<p384::Scalar>::from_bytes(bytes).expect("decoding should succeed");
}
