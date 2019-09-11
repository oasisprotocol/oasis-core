extern crate protoc_grpcio;

fn main() {
    // Storage client (for interoperability tests only).
    let proto_root = "../go/grpc/storage";
    println!("cargo:rerun-if-changed={}/storage.proto", proto_root);

    protoc_grpcio::compile_grpc_protos(
        &["storage.proto"],
        &[proto_root],
        "src/storage/mkvs/urkel/interop/grpc",
        None,
    )
    .expect("Failed to compile gRPC definitions");
}
