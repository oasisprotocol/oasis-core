use oasis_core_keymanager_lib::keymanager::*;
use oasis_core_runtime::{common::version::Version, config::Config, version_from_cargo};

mod api;

pub fn main() {
    let init = new_keymanager(api::trusted_policy_signers());
    oasis_core_runtime::start_runtime(
        init,
        Config {
            version: version_from_cargo!(),
            ..Default::default()
        },
    );
}
