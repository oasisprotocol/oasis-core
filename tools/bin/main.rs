extern crate ansi_term;
#[macro_use]
extern crate clap;
extern crate mktemp;

extern crate ekiden_common;
extern crate ekiden_tools;

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::exit;

use ansi_term::Colour::Red;
use clap::{App, Arg, ArgMatches, SubCommand};

use ekiden_common::error::{Error, Result};
use ekiden_tools::{cargo, get_contract_identity};
use ekiden_tools::contract::ContractBuilder;
use ekiden_tools::utils::SgxMode;

/// Build an Ekiden contract.
fn build_contract(args: &ArgMatches) -> Result<()> {
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
            match args.value_of("target-dir") {
                Some(dir) => Some(Path::new(dir).canonicalize()?),
                None => None,
            },
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
                    return Err(Error::new(
                        "Need to specify one of --version, --git or --path!",
                    ));
                }
            },
        )?,
        None => {
            // Invoke contract-build in the current project directory.
            let project = cargo::ProjectRoot::discover()?;
            let package = match project.get_package() {
                Some(package) => package,
                None => {
                    return Err(Error::new(format!(
                    "manifest path `{}` is a virtual manifest, but this command requires running \
                     against an actual package in this workspace",
                    project.get_config_path().to_str().unwrap()
                )))
                }
            };

            ContractBuilder::new(
                package.name.clone(),
                project.get_target_path().join("contract"),
                match args.value_of("target-dir") {
                    Some(dir) => Some(Path::new(dir).canonicalize()?),
                    None => Some(project.get_target_path()),
                },
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

fn main() {
    let matches = App::new("cargo")
        .subcommand(
            SubCommand::with_name("ekiden")
                .about(crate_description!())
                .author(crate_authors!())
                .version(crate_version!())
                .subcommand(
                    SubCommand::with_name("build-contract")
                        .about("Build an Ekiden contract")
                        .arg(
                            Arg::with_name("contract-crate")
                                .help("Name of the Cargo crate containing the contract")
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("version")
                                .help("Specify a version to build from crates.io")
                                .long("version")
                                .takes_value(true)
                                .conflicts_with("git")
                                .conflicts_with("path"),
                        )
                        .arg(
                            Arg::with_name("git")
                                .help("Git URL to build the specified crate from")
                                .long("git")
                                .takes_value(true)
                                .conflicts_with("version")
                                .conflicts_with("path"),
                        )
                        .arg(
                            Arg::with_name("branch")
                                .help("Branch to use when building from git")
                                .long("branch")
                                .takes_value(true)
                                .requires("git")
                                .conflicts_with("tag")
                                .conflicts_with("rev"),
                        )
                        .arg(
                            Arg::with_name("tag")
                                .help("Tag to use when building from git")
                                .long("tag")
                                .takes_value(true)
                                .requires("git")
                                .conflicts_with("branch")
                                .conflicts_with("rev"),
                        )
                        .arg(
                            Arg::with_name("rev")
                                .help("Specific commit to use when building from git")
                                .long("rev")
                                .takes_value(true)
                                .requires("git")
                                .conflicts_with("branch")
                                .conflicts_with("tag"),
                        )
                        .arg(
                            Arg::with_name("path")
                                .help("Filesystem path to local crate to build")
                                .long("path")
                                .takes_value(true)
                                .conflicts_with("version")
                                .conflicts_with("git"),
                        )
                        .arg(
                            Arg::with_name("release")
                                .long("release")
                                .help("Build contract in release mode, with optimizations"),
                        )
                        .arg(
                            Arg::with_name("sgx-mode")
                                .help("SGX mode")
                                .long("sgx-mode")
                                .takes_value(true)
                                .env("SGX_MODE")
                                .required(true),
                        )
                        .arg(
                            Arg::with_name("intel-sgx-sdk")
                                .help("Path to Intel SGX SDK")
                                .long("intel-sgx-sdk")
                                .takes_value(true)
                                .env("INTEL_SGX_SDK")
                                .required(true),
                        )
                        .arg(
                            Arg::with_name("sign-key")
                                .help(
                                    "Enclave signing key (if not specified, a default key is used)",
                                )
                                .long("sign-key")
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("output")
                                .help("Contract output directory")
                                .long("output")
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("output-identity")
                                .help("Should a contract identity file be generated")
                                .long("output-identity"),
                        )
                        .arg(
                            Arg::with_name("target-dir")
                                .help("Custom location to cache build artifacts")
                                .long("target-dir")
                                .takes_value(true),
                        ),
                ),
        )
        .get_matches();

    if let Some(ref ekiden_matches) = matches.subcommand_matches("ekiden") {
        // Build contract.
        if let Some(ref build_contract_matches) =
            ekiden_matches.subcommand_matches("build-contract")
        {
            match build_contract(build_contract_matches) {
                Ok(()) => {}
                Err(error) => {
                    println!("{} {}", Red.bold().paint("error:"), error);
                    exit(128);
                }
            }
        }
    }
}
