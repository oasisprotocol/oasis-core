fn main() {
    println!("cargo:rerun-if-changed={}", "../xargo/Xargo.toml.template");
    println!(
        "cargo:rerun-if-changed={}",
        "../xargo/x86_64-unknown-linux-sgx.json"
    );
    println!("cargo:rerun-if-changed={}", "../core/edl/src/enclave.lds");
    println!("cargo:rerun-if-changed={}", "../core/edl/src/enclave.xml");
    println!("cargo:rerun-if-changed={}", "../keys/private.pem");
}
