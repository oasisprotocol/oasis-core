extern crate ekiden_edl;
extern crate ekiden_tools;

fn main() {
    ekiden_tools::build_trusted(ekiden_edl::edl());
}
