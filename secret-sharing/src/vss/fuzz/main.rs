use group::ff::PrimeField;
use honggfuzz::fuzz;
use rand::{rngs::StdRng, Rng, SeedableRng};

use secret_sharing::vss::{matrix::VerificationMatrix, polynomial::BivariatePolynomial};

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            fuzz_bivariate_polynomial_random(data);
            fuzz_bivariate_polynomial_from_seed(data);
            fuzz_bivariate_polynomial_from_bytes(data);

            fuzz_verification_matrix_random(data);
            fuzz_verification_matrix_from_seed(data);
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
    assert_eq!(bp, restored)
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

fn fuzz_verification_matrix_random(data: &[u8]) {
    VerificationMatrix::<p384::ProjectivePoint>::from_bytes(data.to_vec());
}

fn fuzz_verification_matrix_from_seed(data: &[u8]) {
    if data.len() < 32 {
        return;
    }

    let bp = random_bivariate_polynomial(data);
    let vm = VerificationMatrix::<p384::ProjectivePoint>::new(&bp); // Slow.
    let restored = VerificationMatrix::<p384::ProjectivePoint>::from_bytes(vm.to_bytes())
        .expect("deserialization should succeed");
    assert_eq!(vm, restored)
}

fn random_bivariate_polynomial<Fp>(data: &[u8]) -> BivariatePolynomial<Fp>
where
    Fp: PrimeField,
{
    let mut seed = [0; 32];
    seed.copy_from_slice(&data[..32]);
    let mut rng = StdRng::from_seed(seed);

    let deg_x = rng.gen_range(0..5);
    let deg_y = rng.gen_range(0..5);

    BivariatePolynomial::<Fp>::random(deg_x, deg_y, &mut rng)
}
