use oasis_core_runtime::common::version::Version;

#[path = "main.rs"]
mod real_main;

fn main() {
    real_main::main_with_version(Version {
        major: 0,
        minor: 1,
        patch: 0,
    })
}
