extern crate ekiden_tools;
extern crate protoc_grpcio;

fn main() {
    // Generate module file.
    // Must be done first to create src/generated directory
    ekiden_tools::generate_mod_with_imports(
        "src/generated",
        &[],
        &["enclaverpc", "enclaverpc_grpc"],
    );

    protoc_grpcio::compile_grpc_protos(&["src/enclaverpc.proto"], &["src"], "src/generated")
        .expect("failed to compile gRPC definitions");

    println!("cargo:rerun-if-changed={}", "src/enclaverpc.proto");
}
