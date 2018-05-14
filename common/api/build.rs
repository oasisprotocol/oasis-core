extern crate ekiden_tools;
#[cfg(not(target_env = "sgx"))]
extern crate protoc_grpcio;

// Note: the conditionals here provide message definitions, but
// only build the grpc service definitions when not in the sgx context.
fn main() {
    // Generate module file.
    // Must be done first to create src/generated directory
    #[cfg(target_env = "sgx")]
    ekiden_tools::generate_mod("src/generated", &["common"]);
    #[cfg(not(target_env = "sgx"))]
    ekiden_tools::generate_mod("src/generated", &["common", "common_grpc"]);

    #[cfg(target_env = "sgx")]
    ekiden_tools::protoc(ekiden_tools::ProtocArgs {
        out_dir: "src/generated/",
        input: &["src/common.proto"],
        includes: &[],
    });
    #[cfg(not(target_env = "sgx"))]
    protoc_grpcio::compile_grpc_protos(&["common.proto"], &["src"], "src/generated")
        .expect("failed to compile gRPC definitions");

    println!("cargo:rerun-if-changed={}", "src/common.proto");
}
