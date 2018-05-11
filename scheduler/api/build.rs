extern crate ekiden_tools;

fn main() {
    // Generate module file.
    // Must be done first to create src/generated directory
    ekiden_tools::generate_mod("src/generated", &["scheduler"]);

    ekiden_tools::protoc(ekiden_tools::ProtocArgs {
        out_dir: "src/generated/",
        input: &["src/scheduler.proto"],
        includes: &[],
    });

    println!("cargo:rerun-if-changed={}", "src/scheduler.proto");
}
