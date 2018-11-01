extern crate ekiden_tools;
extern crate protoc_grpcio;

fn main() {
    // Generate module file.
    // Must be done first to create src/generated directory
    ekiden_tools::generate_mod("src/generated", &["roothash", "roothash_grpc"]);

    // Root set to the core ekiden root so that common/api is in scope.
    protoc_grpcio::compile_grpc_protos(
        &["../../go/grpc/roothash/roothash.proto"],
        &["../../go/grpc"],
        "src/generated",
    ).expect("failed to compile gRPC definitions");

    println!(
        "cargo:rerun-if-changed={}",
        "../../go/grpc/roothash/roothash.proto"
    );
}
