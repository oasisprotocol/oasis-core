extern crate ekiden_tools;
extern crate protoc_grpcio;

fn main() {
    // Generate module file.
    // Must be done first to create src/generated directory
    ekiden_tools::generate_mod_with_imports(
        "src/generated",
        &["common", "consensus"],
        &[
            "computation_group",
            "computation_group_grpc",
            "web3",
            "web3_grpc",
        ],
    );

    protoc_grpcio::compile_grpc_protos(
        &["src/web3.proto", "src/computation_group.proto"],
        &["src", "../../"],
        "src/generated",
    ).expect("failed to compile gRPC definitions");

    println!(
        "cargo:rerun-if-changed={}",
        "../../common/api/src/common.proto"
    );
    println!("cargo:rerun-if-changed={}", "src/web3.proto");
    println!("cargo:rerun-if-changed={}", "src/computation_group.proto");
}
