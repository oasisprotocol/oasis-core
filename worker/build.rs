extern crate ekiden_edl;
extern crate ekiden_tools;

fn main() {
    ekiden_tools::build_untrusted(ekiden_edl::get_edls().unwrap());
}
