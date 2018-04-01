extern crate ekiden_tools;

fn main() {
    ekiden_tools::generate_mod_with_imports(
        "src/generated",
        &["ekiden_enclave_common::generated::enclave_identity"],
        &["enclave_rpc"],
    );

    ekiden_tools::protoc(ekiden_tools::ProtocArgs {
        out_dir: "src/generated/",
        input: &["src/enclave_rpc.proto"],
        includes: &["src/", "../../enclave/common/src/"],
    });
}
