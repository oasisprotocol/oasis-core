use std::fs::OpenOptions;
use std::io::prelude::*;

extern crate ekiden_tools;
extern crate protoc_grpcio;

// Note: the conditionals here provide message definitions, but
// only build the grpc service definitions when not in the sgx context.
fn main() {
    // Generate module file.
    // Must be done first to create src/generated directory
    ekiden_tools::generate_mod("src/generated", &["common"]);

    // Only link 'common_grpc' conditionally when in non-sgx uses.
    let mut file = OpenOptions::new()
        .append(true)
        .open("src/generated/mod.rs")
        .expect("Failed to append module file");
    writeln!(&mut file, "#[cfg(not(target_env = \"sgx\"))]").unwrap();
    writeln!(&mut file, "pub mod common_grpc;").unwrap();

    protoc_grpcio::compile_grpc_protos(&["common.proto"], &["src"], "src/generated")
        .expect("failed to compile gRPC definitions");

    println!("cargo:rerun-if-changed={}", "src/common.proto");
}
