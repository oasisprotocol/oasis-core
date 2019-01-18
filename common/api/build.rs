extern crate ekiden_tools;

fn main() {
    // Generate module file.
    // Must be done first to create src/generated directory
    ekiden_tools::generate_mod("src/generated", &["common"]);

    ekiden_tools::protoc(ekiden_tools::ProtocArgs {
        out_dir: "src/generated/",
        input: &["../../go/grpc/common/common.proto"],
        includes: &["../../go/grpc"],
    });

    println!(
        "cargo:rerun-if-changed={}",
        "../../go/grpc/common/common.proto"
    );
}
