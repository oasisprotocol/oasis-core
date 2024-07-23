use group::ff::PrimeField;
use honggfuzz::fuzz;
use rand::{rngs::StdRng, Rng, SeedableRng};

use secret_sharing::{poly::BivariatePolynomial, vss::VerificationMatrix};

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            fuzz_verification_matrix_random(data);
            fuzz_verification_matrix_from_seed(data);
        });
    }
}

fn fuzz_verification_matrix_random(data: &[u8]) {
    VerificationMatrix::<p384::ProjectivePoint>::from_bytes(data);
}

fn fuzz_verification_matrix_from_seed(data: &[u8]) {
    if data.len() < 32 {
        return;
    }

    let bp = random_bivariate_polynomial(data);
    let vm = VerificationMatrix::<p384::ProjectivePoint>::from(&bp); // Slow.
    let restored = VerificationMatrix::<p384::ProjectivePoint>::from_bytes(&vm.to_bytes())
        .expect("deserialization should succeed");
    assert_eq!(vm, restored)
}

fn random_bivariate_polynomial<F: PrimeField>(data: &[u8]) -> BivariatePolynomial<F> {
    let mut seed = [0; 32];
    seed.copy_from_slice(&data[..32]);
    let mut rng = StdRng::from_seed(seed);

    let deg_x = rng.gen_range(0..5);
    let deg_y = rng.gen_range(0..5);

    BivariatePolynomial::<F>::random(deg_x, deg_y, &mut rng)
}
