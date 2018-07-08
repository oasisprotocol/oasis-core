extern crate ekiden_tools;

fn main() {
    ekiden_tools::generate_mod("src/abci/generated", &["types"]);

    ekiden_tools::protoc(ekiden_tools::ProtocArgs {
        out_dir: "src/abci/generated/",
        input: &["src/abci/types.proto"],
        includes: &["src/abci"],
    });
}
