extern crate ekiden_tools;

fn main() {
    ekiden_tools::generate_mod("src/generated", &["api"]);
    ekiden_tools::build_api();
}
