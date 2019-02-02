extern crate ekiden_tools;
extern crate protoc_grpcio;

fn main() {
    // Generate module file.
    // Must be done first to create src/generated directory
    ekiden_tools::generate_mod("src/generated", &["runtime", "runtime_grpc"]);

    protoc_grpcio::compile_grpc_protos(
        &["../../go/grpc/committee/runtime.proto"],
        &["src", "../../go/grpc"],
        "src/generated",
    )
    .expect("failed to compile gRPC definitions");

    println!(
        "cargo:rerun-if-changed={}",
        "../../go/grpc/committee/runtime.proto"
    );
}
