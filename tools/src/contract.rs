//! Ekiden contract builder.
use std;
use std::env;
use std::fs::{DirBuilder, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use ansi_term::Colour::Green;
use mktemp::Temp;

use ekiden_common::error::{Error, Result};

use super::cargo;
use super::utils::SgxMode;

/// Xargo configuration file.
static XARGO_CONFIG: &'static str = include_str!("../../xargo/Xargo.toml.template");
/// Xargo target descriptor.
static XARGO_TARGET: &'static str = include_str!("../../xargo/x86_64-unknown-linux-sgx.json");
/// Linker version script.
static LINKER_VERSION_SCRIPT: &'static str = include_str!("../../core/edl/src/enclave.lds");
/// Enclave self.
static ENCLAVE_CONFIG: &'static str = include_str!("../../core/edl/src/enclave.xml");
/// Default enclave signing key.
static ENCLAVE_SIGNING_KEY: &'static str = include_str!("../../keys/private.pem");

/// Name of subdirectory in the target directory.
const TARGET_CONTRACT_DIR: &'static str = "contract";

/// Contract build configuration.
pub struct ContractBuilder<'a> {
    /// Name of the crate being built.
    crate_name: String,
    /// Output directory path.
    output_path: PathBuf,
    /// Build directory path.
    build_path: PathBuf,
    /// Ownership over build directory path (directory is removed when dropped).
    #[allow(dead_code)]
    build_temporary_dir: Temp,
    /// Target directory path.
    target_path: PathBuf,
    /// Source crate location.
    source: Box<cargo::CrateSource + 'a>,
    /// Path of a file to append to the dummy top-level Cargo.toml.
    cargo_addendum: Option<PathBuf>,
    /// Build verbosity.
    verbose: bool,
    /// Release mode.
    release: bool,
    /// Path to Intel SGX SDK.
    intel_sgx_sdk: Option<PathBuf>,
    /// SGX build mode.
    sgx_mode: SgxMode,
    /// Signing key location.
    signing_key: Option<PathBuf>,
}

impl<'a> ContractBuilder<'a> {
    pub fn new(
        crate_name: String,
        output_path: PathBuf,
        target_path: Option<PathBuf>,
        source: Box<cargo::CrateSource + 'a>,
        cargo_addendum: Option<PathBuf>,
    ) -> Result<Self> {
        let build_temporary_dir = Temp::new_dir()?;
        let build_path = build_temporary_dir.to_path_buf();

        Ok(ContractBuilder {
            crate_name,
            output_path,
            build_path: build_path.clone(),
            build_temporary_dir,
            target_path: target_path.unwrap_or(build_path.join("target")),
            source,
            cargo_addendum,
            verbose: false,
            release: false,
            intel_sgx_sdk: match env::var("INTEL_SGX_SDK") {
                Ok(value) => Some(Path::new(&value).to_path_buf()),
                Err(_) => None,
            },
            sgx_mode: match env::var("SGX_MODE") {
                Ok(ref value) => if value == "HW" {
                    SgxMode::Hardware
                } else {
                    SgxMode::Simulation
                },
                _ => SgxMode::Simulation,
            },
            signing_key: None,
        })
    }

    /// Get crate name.
    pub fn get_crate_name(&self) -> &str {
        self.crate_name.as_str()
    }

    /// Get output path.
    pub fn get_output_path(&self) -> &PathBuf {
        &self.output_path
    }

    /// Get build path.
    pub fn get_build_path(&self) -> &PathBuf {
        &self.build_path
    }

    /// Get contract target path.
    pub fn get_contract_target_path(&self) -> PathBuf {
        self.target_path.join(TARGET_CONTRACT_DIR)
    }

    /// Set builder verbosity.
    pub fn verbose(&mut self, verbose: bool) -> &mut Self {
        self.verbose = verbose;
        self
    }

    /// Set release mode.
    pub fn release(&mut self, mode: bool) -> &mut Self {
        self.release = mode;
        self
    }

    /// Set path to Intel SGX SDK.
    ///
    /// By default this will be configured based on the `INTEL_SGX_SDK` environment
    /// variable.
    pub fn intel_sgx_sdk<P: Into<PathBuf>>(&mut self, path: P) -> &mut Self {
        self.intel_sgx_sdk = Some(path.into());
        self
    }

    /// Set SGX build mode.
    ///
    /// By default this will be configured based on the `SGX_MODE` environment
    /// variable.
    pub fn sgx_mode(&mut self, mode: SgxMode) -> &mut Self {
        self.sgx_mode = mode;
        self
    }

    /// Set SGX enclave signing key.
    ///
    /// By default a pre-defined signing key is used.
    pub fn signing_key<P: Into<PathBuf>>(&mut self, key: Option<P>) -> &mut Self {
        self.signing_key = match key {
            Some(path) => Some(path.into()),
            None => None,
        };
        self
    }

    /// Output progress update if verbose mode is enabled.
    fn report_stage(&self, stage: &str) {
        if !self.verbose {
            return;
        }

        println!(
            "{} {}",
            Green.bold().paint(format!("{:>12}", stage)),
            self.crate_name,
        );
    }

    /// Prepare and build the contract static library crate.
    ///
    /// This generates a temporary directory with a new crate that lists only
    /// the source contract crate as a dependency. It is made so that it
    /// generates a static library when built.
    pub fn build_contract_crate(&self) -> Result<()> {
        self.report_stage("Preparing");

        // Prepare dummy crate.
        let mut cargo_toml = File::create(&self.build_path.join("Cargo.toml"))?;
        writeln!(&mut cargo_toml, "[package]")?;
        writeln!(&mut cargo_toml, "name = \"contract_enclave\"")?;
        writeln!(&mut cargo_toml, "version = \"0.0.0\"")?;
        writeln!(&mut cargo_toml, "")?;
        writeln!(&mut cargo_toml, "[lib]")?;
        writeln!(&mut cargo_toml, "path = \"lib.rs\"")?;
        writeln!(&mut cargo_toml, "crate-type = [\"staticlib\"]")?;
        writeln!(&mut cargo_toml, "")?;
        writeln!(&mut cargo_toml, "[dependencies]")?;
        write!(&mut cargo_toml, "{} = ", self.crate_name)?;
        self.source.write_location(&mut cargo_toml)?;
        if let Some(cargo_addendum_path) = self.cargo_addendum.as_ref() {
            let mut cargo_addendum = File::open(cargo_addendum_path)?;
            std::io::copy(&mut cargo_addendum, &mut cargo_toml)?;
        }
        drop(cargo_toml);

        // Include Xargo configuration files.
        let mut xargo_toml = File::create(&self.build_path.join("Xargo.toml"))?;
        write!(&mut xargo_toml, "{}", XARGO_CONFIG)?;
        drop(xargo_toml);

        let mut xargo_target =
            File::create(&self.build_path.join("x86_64-unknown-linux-sgx.json"))?;
        write!(&mut xargo_target, "{}", XARGO_TARGET)?;
        drop(xargo_target);

        let mut lib_rs = File::create(&self.build_path.join("lib.rs"))?;
        writeln!(
            &mut lib_rs,
            "extern crate {};",
            self.crate_name.replace("-", "_")
        )?;

        // Build the crate using Xargo to get the staticlib.
        self.report_stage("Building");

        let mut xargo = Command::new("xargo");
        xargo.arg("build");

        if self.release {
            xargo.arg("--release");
        }

        let xargo_status = xargo
            .arg("--target")
            .arg("x86_64-unknown-linux-sgx")
            // TODO: Combine rustflags.
            .env("RUSTFLAGS", "-Z force-unstable-if-unmarked")
            .env("RUST_TARGET_PATH", &self.build_path)
            .env("CARGO_TARGET_DIR", &self.target_path)
            .current_dir(&self.build_path)
            .status()?;
        if !xargo_status.success() {
            return Err(Error::new(format!(
                "failed to build, xargo exited with status {}!",
                xargo_status.code().unwrap()
            )));
        }

        Ok(())
    }

    /// Link the generated static library with SGX libraries.
    pub fn link_enclave(&self) -> Result<()> {
        self.report_stage("Linking");

        // Include linker version script.
        let enclave_lds_path = self.build_path.join("enclave.lds");
        let mut enclave_lds = File::create(&enclave_lds_path)?;
        write!(&mut enclave_lds, "{}", LINKER_VERSION_SCRIPT)?;
        drop(enclave_lds);

        // Configure Intel SGX SDK path and library names.
        let intel_sgx_sdk_lib_path = match self.intel_sgx_sdk {
            Some(ref sdk) => sdk.join("lib64"),
            None => return Err(Error::new("path to Intel SGX SDK not configured")),
        };
        let (trts_library_name, service_library_name) = match self.sgx_mode {
            SgxMode::Hardware => ("sgx_trts", "sgx_tservice"),
            SgxMode::Simulation => ("sgx_trts_sim", "sgx_tservice_sim"),
        };

        // Determine enclave library path.
        let library_path = if self.release {
            self.target_path.join("x86_64-unknown-linux-sgx/release")
        } else {
            self.target_path.join("x86_64-unknown-linux-sgx/debug")
        };

        // Ensure contract target path is available.
        DirBuilder::new()
            .recursive(true)
            .create(&self.get_contract_target_path())?;

        let gcc_status = Command::new("g++")
            .arg("-Wl,--no-undefined")
            .arg("-nostdlib")
            .arg("-nodefaultlibs")
            .arg("-nostartfiles")
            .arg(&format!("-L{}", intel_sgx_sdk_lib_path.to_str().unwrap()))
            .arg(&format!("-L{}", library_path.to_str().unwrap()))
            // Trusted runtime group.
            .arg("-Wl,--whole-archive")
            .arg(&format!("-l{}", trts_library_name))
            .arg("-Wl,--no-whole-archive")
            // Enclave library group.
            .arg("-Wl,--start-group")
            .arg("-lsgx_tstdc")
            .arg("-lsgx_tstdcxx")
            .arg("-lsgx_tcrypto")
            .arg("-lsgx_tkey_exchange")
            .arg(&format!("-l{}", service_library_name))
            .arg("-lcontract_enclave")
            .arg("-Wl,--end-group")
            .arg("-Wl,-Bstatic")
            .arg("-Wl,-Bsymbolic")
            .arg("-Wl,--no-undefined")
            .arg("-Wl,-pie,-eenclave_entry")
            .arg("-Wl,--export-dynamic")
            .arg("-Wl,--defsym,__ImageBase=0")
            // Require __ekiden_enclave symbol to be defined.
            .arg("-Wl,--require-defined,__ekiden_enclave")
            .arg("-Wl,--gc-sections")
            .arg(&format!("-Wl,--version-script={}", enclave_lds_path.to_str().unwrap()))
            .arg("-O2")
            .arg("-o")
            .arg(self.get_contract_target_path()
                .join(format!("{}.unsigned.so", self.crate_name)).to_str().unwrap())
            .current_dir(&self.build_path)
            .status()?;
        if !gcc_status.success() {
            return Err(Error::new(format!(
                "failed to link, g++ exited with status {}!",
                gcc_status.code().unwrap()
            )));
        }

        Ok(())
    }

    /// Sign the generated enclave library.
    pub fn sign_enclave(&self) -> Result<()> {
        self.report_stage("Signing");

        // Include enclave configuration.
        let enclave_config_path = self.build_path.join("enclave.xml");
        let mut enclave_config = File::create(&enclave_config_path)?;
        write!(&mut enclave_config, "{}", ENCLAVE_CONFIG)?;
        drop(enclave_config);

        let signer_path = match self.intel_sgx_sdk {
            Some(ref sdk) => sdk.join("bin/x64/sgx_sign"),
            None => return Err(Error::new("path to Intel SGX SDK not configured")),
        };

        // Determine signing key.
        let key_path = match self.signing_key {
            Some(ref key) => key.clone(),
            None => {
                // Include default enclave signing key.
                let enclave_key_path = self.build_path.join("enclave.pem");
                let mut enclave_key = File::create(&enclave_key_path)?;
                write!(&mut enclave_key, "{}", ENCLAVE_SIGNING_KEY)?;

                enclave_key_path
            }
        };

        // Ensure contract output path is available.
        DirBuilder::new().recursive(true).create(&self.output_path)?;

        let signer_status = Command::new(signer_path)
            .arg("sign")
            .arg("-key")
            .arg(&key_path)
            .arg("-enclave")
            .arg(&self.get_contract_target_path()
                .join(format!("{}.unsigned.so", self.crate_name)))
            .arg("-out")
            .arg(&self.output_path.join(format!("{}.so", self.crate_name)))
            .arg("-config")
            .arg(&enclave_config_path)
            .status()?;
        if !signer_status.success() {
            return Err(Error::new(format!(
                "failed to sign, sgx_sign exited with status {}!",
                signer_status.code().unwrap()
            )));
        }

        Ok(())
    }

    /// Performs all the contract build steps.
    pub fn build(&self) -> Result<()> {
        self.build_contract_crate()?;
        self.link_enclave()?;
        self.sign_enclave()?;

        Ok(())
    }
}
