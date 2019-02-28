extern crate ekiden_keymanager_edl;
extern crate ekiden_tools;

fn main() {
    ekiden_tools::build_untrusted(ekiden_keymanager_edl::get_edls().unwrap());
}
