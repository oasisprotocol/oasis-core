extern crate ekiden_tools;
extern crate protoc_grpcio;

fn main() {
    ekiden_tools::detect_sgx_features();

    ekiden_tools::generate_mod_with_imports("src/generated", &["common"], &["ias", "ias_grpc"]);

    protoc_grpcio::compile_grpc_protos(
        &["../../go/grpc/ias/ias.proto"],
        &["../../go/grpc"],
        "src/generated",
    ).expect("failed to compile gRPC definitions");

    println!("cargo:rerun-if-changed={}", "../../go/grpc/ias/ias.proto");
    println!(
        "cargo:rerun-if-changed={}",
        "../../go/grpc/common/common.proto"
    );
}
