//! Tool subcommand for building contracts.
extern crate clap;

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use self::clap::ArgMatches;

use super::cargo;
use super::contract::ContractBuilder;
use super::error::Result;

use utils::{get_contract_identity, SgxMode};

/// Build an Ekiden contract.
pub fn build_contract(args: &ArgMatches) -> Result<()> {
    let mut builder = match args.value_of("contract-crate") {
        Some(crate_name) => ContractBuilder::new(
            // Crate name.
            crate_name.to_owned(),
            // Output directory.
            match args.value_of("output") {
                Some(ref output) => Path::new(output).to_path_buf(),
                None => env::current_dir()?,
            },
            // Target directory.
            None,
            // Contract crate source.
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
        )?,
        None => {
            // Invoke contract-build in the current project directory.
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

            ContractBuilder::new(
                package.name.clone(),
                project.get_target_path().join("contract"),
                Some(project.get_target_path()),
                Box::new(cargo::PathSource {
                    path: project.get_path(),
                }),
            )?
        }
    };

    // Configure builder.
    builder
        .verbose(true)
        .release(args.is_present("release"))
        .intel_sgx_sdk(Path::new(args.value_of("intel-sgx-sdk").unwrap()))
        .sgx_mode(match args.value_of("sgx-mode") {
            Some("HW") => SgxMode::Hardware,
            _ => SgxMode::Simulation,
        })
        .signing_key(args.value_of("sign-key"));

    // Build contract.
    builder.build()?;

    // Output enclave identity when required.
    if args.is_present("output-identity") {
        let identity = get_contract_identity(
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
