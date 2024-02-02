use oasis_core_keymanager::runtime::init::new_keymanager;
use oasis_core_runtime::{
    common::version::Version, config::Config, consensus::verifier::TrustRoot,
};

mod api;

pub fn main_with_version(version: Version) {
    // Initializer.
    let init = new_keymanager(api::trusted_policy_signers());

    // Determine test trust root based on build settings.
    #[allow(clippy::option_env_unwrap)]
    let trust_root = option_env!("OASIS_TESTS_CONSENSUS_TRUST_HEIGHT").map(|height| {
        let hash = option_env!("OASIS_TESTS_CONSENSUS_TRUST_HASH").unwrap();
        let runtime_id = option_env!("OASIS_TESTS_CONSENSUS_TRUST_RUNTIME_ID").unwrap();
        let chain_context = option_env!("OASIS_TESTS_CONSENSUS_TRUST_CHAIN_CONTEXT").unwrap();

        TrustRoot {
            height: height.parse::<u64>().unwrap(),
            hash: hash.to_string(),
            runtime_id: runtime_id.into(),
            chain_context: chain_context.to_string(),
        }
    });

    // Start the runtime.
    oasis_core_runtime::start_runtime(
        init,
        Config {
            version,
            trust_root,
            ..Default::default()
        },
    );
}

#[allow(dead_code)]
pub fn main() {
    main_with_version(Version {
        major: 0,
        minor: 0,
        patch: 0,
    })
}
