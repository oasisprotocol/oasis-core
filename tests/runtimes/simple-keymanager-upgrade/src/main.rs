use oasis_core_keymanager_lib::keymanager::*;
use oasis_core_runtime::{common::version::Version, version_from_cargo};

mod api;

fn main() {
    let init = new_keymanager(api::trusted_policy_signers());
    oasis_core_runtime::start_runtime(init, version_from_cargo!());
}
