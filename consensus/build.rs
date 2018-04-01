extern crate ekiden_tools;
extern crate protoc_rust_grpc;

fn main() {
    // Generate module file.
    // Must be done first to create src/generated directory
    ekiden_tools::generate_mod("src/generated", &["tendermint", "tendermint_grpc"]);

    protoc_rust_grpc::run(protoc_rust_grpc::Args {
        out_dir: "src/generated/",
        includes: &[],
        input: &["src/tendermint.proto"],
        rust_protobuf: true,
    }).expect("protoc-rust-grpc");
}
