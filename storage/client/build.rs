extern crate ekiden_tools;
extern crate protoc_grpcio;

fn main() {
    // Must be done first to create src/generated directory
    ekiden_tools::generate_mod("src/generated", &["storage", "storage_grpc"]);

    protoc_grpcio::compile_grpc_protos(
        &["../../go/grpc/storage/storage.proto"],
        &["../../go/grpc"],
        "src/generated",
    )
    .expect("failed to compile gRPC definitions");

    println!(
        "cargo:rerun-if-changed={}",
        "../../go/grpc/storage/storage.proto"
    );
}
