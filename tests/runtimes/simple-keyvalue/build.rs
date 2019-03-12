use ekiden_tools::sgxs::generate_enclave_hash;

fn main() {
    // Generate key manager enclave hash for inclusion as OUT_DIR/km_enclave_hash.rs.
    generate_enclave_hash("KM", "Key manager").unwrap();
}
