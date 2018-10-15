//! Tool subcommand for building enclaves.
extern crate clap;

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use self::clap::ArgMatches;

use super::cargo;
use super::enclave::{EnclaveBuilder, TARGET_ENCLAVE_DIR};
use super::error::Result;

use utils::{get_enclave_identity, SgxMode};

/// Build an Ekiden enclave.
pub fn build_enclave(args: &ArgMatches) -> Result<()> {
    let cargo_addendum = args.value_of("cargo-addendum")
        .map(|path| PathBuf::from(path));

    let mut builder = match args.value_of("enclave-crate") {
        Some(crate_name) => EnclaveBuilder::new(
            // Crate name.
            crate_name.to_owned(),
            // Output directory.
            match args.value_of("output") {
                Some(ref output) => Path::new(output).to_path_buf(),
                None => env::current_dir()?,
            },
            // Target directory.
            match args.value_of("target-dir") {
                Some(dir) => Some(Path::new(dir).canonicalize()?),
                None => None,
            },
            // Enclave crate source.
            {
                if let Some(version) = args.value_of("version") {
                    Box::new(cargo::VersionSource { version: version })
                } else if let Some(git) = args.value_of("git") {
                    Box::new(cargo::GitSource {
                        repository: git,
                        branch: args.value_of("branch"),
                        tag: args.value_of("tag"),
                        rev: args.value_of("rev"),
                    })
                } else if let Some(path) = args.value_of("path") {
                    Box::new(cargo::PathSource {
                        path: Path::new(path).canonicalize()?,
                    })
                } else {
                    return Err("need to specify one of --version, --git or --path!".into());
                }
            },
            cargo_addendum,
            None,
        )?,
        None => {
            // Invoke enclave-build in the current project directory.
            let project = cargo::ProjectRoot::discover()?;
            let package = match project.get_package() {
                Some(package) => package,
                None => {
                    return Err(format!(
                    "manifest path `{}` is a virtual manifest, but this command requires running \
                     against an actual package in this workspace",
                    project.get_config_path().to_str().unwrap()
                ).into())
                }
            };
            if args.is_present("output") {
                return Err("The --output option is not used when implicitly \
                            building the current project directory."
                    .into());
            }

            EnclaveBuilder::new(
                package.name.clone(),
                project.get_target_path().join(TARGET_ENCLAVE_DIR),
                match args.value_of("target-dir") {
                    Some(dir) => Some(Path::new(dir).canonicalize()?),
                    None => Some(project.get_target_path()),
                },
                Box::new(cargo::PathSource {
                    path: project.get_path(),
                }),
                cargo_addendum,
                // We currently cannot use a workspace-wide Cargo.lock because if we build
                // multiple enclaves, the lock files would be overwritten.
                Some(project.get_path().join("Cargo.enclave.lock")),
            )?
        }
    };

    // Configure builder.
    builder
        .verbose(args.occurrences_of("verbose") > 0)
        .release(args.is_present("release"))
        .intel_sgx_sdk(Path::new(args.value_of("intel-sgx-sdk").unwrap()))
        .sgx_mode(match args.value_of("sgx-mode") {
            Some("HW") => SgxMode::Hardware,
            _ => SgxMode::Simulation,
        })
        .signing_key(args.value_of("sign-key"))
        .cargo_args(
            args.values_of("cargo-args")
                .map(|args| args.collect())
                .unwrap_or_default(),
        );

    // Build enclave.
    builder.build()?;

    // Output enclave identity when required.
    if args.is_present("output-identity") {
        let identity = get_enclave_identity(
            builder
                .get_output_path()
                .join(format!("{}.so", builder.get_crate_name())),
        )?;

        // Hex encode identity.
        let identity_file_path = builder
            .get_output_path()
            .join(format!("{}.mrenclave", builder.get_crate_name()));
        let mut identity_file = File::create(&identity_file_path)?;
        for byte in &identity {
            write!(&mut identity_file, "{:02x}", byte)?;
        }
    }

    Ok(())
}
