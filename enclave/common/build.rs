extern crate ekiden_tools;

fn main() {
    ekiden_tools::generate_mod("src/generated", &["enclave_identity"]);

    ekiden_tools::protoc(ekiden_tools::ProtocArgs {
        out_dir: "src/generated/",
        input: &["src/enclave_identity.proto"],
        includes: &["src/"],
    });
}
