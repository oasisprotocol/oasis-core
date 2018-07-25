extern crate ekiden_tools;

fn main() {
    // Generate module file.
    // Must be done first to create src/generated directory
    ekiden_tools::generate_mod("src/generated", &["api"]);

    ekiden_tools::build_api();

    println!("cargo:rerun-if-changed={}", "src/api.proto");
}
