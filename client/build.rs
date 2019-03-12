extern crate protoc_grpcio;

fn main() {
    // Transaction client.
    let proto_root = "../go/grpc/client";
    println!("cargo:rerun-if-changed={}/client.proto", proto_root);

    protoc_grpcio::compile_grpc_protos(
        &["client.proto"],
        &[proto_root],
        "src/transaction/api",
        None,
    )
    .expect("Failed to compile gRPC definitions");

    // Storage client.
    let proto_root = "../go/grpc/storage";
    println!("cargo:rerun-if-changed={}/storage.proto", proto_root);

    protoc_grpcio::compile_grpc_protos(
        &["storage.proto"],
        &[proto_root],
        "src/transaction/api",
        None,
    )
    .expect("Failed to compile gRPC definitions");

    // RPC client.
    let proto_root = "../go/grpc/enclaverpc";
    println!("cargo:rerun-if-changed={}/enclaverpc.proto", proto_root);

    protoc_grpcio::compile_grpc_protos(&["enclaverpc.proto"], &[proto_root], "src/rpc/api", None)
        .expect("Failed to compile gRPC definitions");
}
