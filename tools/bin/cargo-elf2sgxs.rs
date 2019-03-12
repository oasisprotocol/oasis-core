//! Cargo-aware elf2sgxs wrapper.
extern crate ansi_term;
extern crate clap;
extern crate failure;
extern crate serde;
extern crate serde_derive;

use std::{
    fs, io,
    process::{exit, Command, ExitStatus},
};

use ansi_term::Color::{Green, Red, White};
use clap::{App, Arg, SubCommand};
use ekiden_tools::cargo;
use failure::{format_err, Fail, Fallible, ResultExt};

/// Target tripe for SGX platform.
const TARGET_TRIPLE: &'static str = "x86_64-fortanix-unknown-sgx";
/// Default heap size.
const DEFAULT_HEAP_SIZE: u64 = 0x2000000;
/// Default SSA frame size.
const DEFAULT_SSAFRAMESIZE: u32 = 1;
/// Default stack size.
const DEFAULT_STACK_SIZE: u32 = 0x20000;
/// Default number of threads.
const DEFAULT_THREADS: u32 = 2;
/// Default value of debug mode for SGX enclaves.
const DEFAULT_DEBUG: bool = true;

#[derive(Debug, Fail)]
enum CommandFail {
    #[fail(display = "failed to run {}, {}", _0, _1)]
    Io(String, io::Error),
    #[fail(display = "while running {} got {}", _0, _1)]
    Status(String, ExitStatus),
}

fn run_command(mut cmd: Command) -> Result<(), CommandFail> {
    match cmd.status() {
        Err(e) => Err(CommandFail::Io(format!("{:?}", cmd), e)),
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(CommandFail::Status(format!("{:?}", cmd), status)),
    }
}

fn real_main() -> Fallible<()> {
    let matches = App::new("cargo")
        .subcommand(
            SubCommand::with_name("elf2sgxs").arg(
                Arg::with_name("release")
                    .long("release")
                    .help("Use release build artifacts"),
            ),
        )
        .get_matches();

    let matches = match matches.subcommand_matches("elf2sgxs") {
        Some(matches) => matches,
        None => return Ok(()),
    };

    let package_root = cargo::PackageRoot::discover()?;
    if !package_root.is_package() {
        return Err(format_err!(
            "manifest path `{}` is a virtual manifest, but this command requires running \
             against an actual package in this workspace",
            package_root.manifest_path().to_str().unwrap(),
        ));
    }
    let package = package_root.package().unwrap();

    // Build target path.
    let mut target_path = package_root.target_path();
    target_path.push(TARGET_TRIPLE);
    if matches.is_present("release") {
        target_path.push("release");
    } else {
        target_path.push("debug");
    }
    // TODO: Discover binary name (what cargo does).
    target_path.push(&package.name);

    // Populate elf2sgxs arguments.
    let config = &package.metadata.fortanix_sgx;
    let heap_size = config.heap_size.unwrap_or(DEFAULT_HEAP_SIZE).to_string();
    let ssaframesize = config
        .ssaframesize
        .unwrap_or(DEFAULT_SSAFRAMESIZE)
        .to_string();
    let stack_size = config.stack_size.unwrap_or(DEFAULT_STACK_SIZE).to_string();
    let threads = config.threads.unwrap_or(DEFAULT_THREADS).to_string();
    let debug = config.debug.unwrap_or(DEFAULT_DEBUG);

    // Invoke ftx-elf2sgxs binary to perform the actual conversion.
    println!(
        "{} {} {} ({})",
        Green.bold().paint(format!("{:>12}", "elf2sgxs")),
        package.name,
        package.version,
        package_root.package_path().to_str().unwrap(),
    );

    // Compare source and target modification times and do not do anything
    // if the target is newer.
    let src_meta = fs::metadata(&target_path).context(format!(
        "source file ({}) not found",
        target_path.to_str().unwrap()
    ))?;
    if let Ok(target_meta) = fs::metadata(target_path.with_extension("sgxs")) {
        let src_modified = src_meta.modified()?;
        let target_modified = target_meta.modified()?;

        if target_modified > src_modified {
            println!(
                "{} {}",
                Green.bold().paint(format!("{:>12}", "elf2sgxs")),
                White.dimmed().paint("(skipped due to newer target file)"),
            );
            return Ok(());
        }
    }

    let mut ftxsgx_elf2sgxs_command = Command::new("ftxsgx-elf2sgxs");
    ftxsgx_elf2sgxs_command
        .arg(target_path.to_str().unwrap())
        .arg("--heap-size")
        .arg(heap_size)
        .arg("--ssaframesize")
        .arg(ssaframesize)
        .arg("--stack-size")
        .arg(stack_size)
        .arg("--threads")
        .arg(threads);
    if debug {
        ftxsgx_elf2sgxs_command.arg("--debug");
    }
    run_command(ftxsgx_elf2sgxs_command)?;

    Ok(())
}

fn main() {
    if let Err(error) = real_main() {
        println!("{} {}", Red.bold().paint("error:"), error);
        exit(128);
    }
}
