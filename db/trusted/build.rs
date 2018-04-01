extern crate ekiden_tools;

fn main() {
    ekiden_tools::generate_mod("src/generated", &["database"]);

    ekiden_tools::protoc(ekiden_tools::ProtocArgs {
        out_dir: "src/generated/",
        input: &["src/database.proto"],
        includes: &["src/"],
    });
}
