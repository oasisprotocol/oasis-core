//! Ekiden build utilities.
use std::env;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::path::Path;
use std::process::Command;

use cc;
use filebuffer::FileBuffer;
use mktemp;
use protobuf;
use protoc_rust;
use regex::bytes::Regex;

use super::error::Result;

/// Arguments for protoc.
#[derive(Debug, Default)]
pub struct ProtocArgs<'a> {
    /// --lang_out= param
    pub out_dir: &'a str,
    /// -I args
    pub includes: &'a [&'a str],
    /// List of .proto files to compile
    pub input: &'a [&'a str],
}

/// SGX build mode.
pub enum SgxMode {
    Hardware,
    Simulation,
}

/// Build part.
enum BuildPart {
    Untrusted,
    Trusted,
}

/// Build configuration.
struct BuildConfiguration {
    mode: SgxMode,
    intel_sdk_dir: String,
}

// Paths.
static EDGER8R_PATH: &'static str = "bin/x64/sgx_edger8r";
static SGX_SDK_LIBRARY_PATH: &'static str = "lib64";
static SGX_SDK_INCLUDE_PATH: &'static str = "include";
static SGX_SDK_TLIBC_INCLUDE_PATH: &'static str = "include/tlibc";
static SGX_SDK_STLPORT_INCLUDE_PATH: &'static str = "include/stlport";
static SGX_SDK_EPID_INCLUDE_PATH: &'static str = "include/epid";

/// Get current build environment configuration.
fn get_build_configuration() -> BuildConfiguration {
    // Ensure build script is restarted if any of the env variables changes.
    println!("cargo:rerun-if-env-changed=SGX_MODE");
    println!("cargo:rerun-if-env-changed=INTEL_SGX_SDK");

    BuildConfiguration {
        mode: match env::var("SGX_MODE")
            .expect("Please define SGX_MODE")
            .as_ref()
        {
            "HW" => SgxMode::Hardware,
            _ => SgxMode::Simulation,
        },
        intel_sdk_dir: env::var("INTEL_SGX_SDK").expect("Please define INTEL_SGX_SDK"),
    }
}

/// Run edger8r tool from Intel SGX SDK.
fn edger8r(
    config: &BuildConfiguration,
    part: BuildPart,
    output: &str,
    edls: &sgx_edl::EDLs,
) -> io::Result<()> {
    println!("{:?}", edls);
    let edl_filename = Path::new(&output).join("enclave.edl");
    let edger8r_bin = Path::new(&config.intel_sdk_dir).join(EDGER8R_PATH);
    let mut edger8 = Command::new(edger8r_bin.to_str().unwrap());
    edger8
        .args(&["--search-path", output])
        .args(&[
            "--search-path",
            Path::new(&config.intel_sdk_dir)
                .join(SGX_SDK_INCLUDE_PATH)
                .to_str()
                .unwrap(),
        ])
        .args(&match part {
            BuildPart::Untrusted => ["--untrusted", "--untrusted-dir", &output],
            BuildPart::Trusted => ["--trusted", "--trusted-dir", &output],
        })
        .arg(edl_filename.to_str().unwrap());
    for search_path in edls.search_paths.iter() {
        edger8.args(&["--search-path", search_path.to_str().unwrap()]);
    }

    // Create temporary files with all sgx_edl::EDLs and import all of them in the core EDL.
    {
        let mut enclave_edl_file = fs::File::create(&edl_filename)?;
        writeln!(&mut enclave_edl_file, "enclave {{").unwrap();
        for ref edl_path in edls.edl_paths.iter() {
            writeln!(
                &mut enclave_edl_file,
                "from \"{}\" import *;",
                edl_path.file_name().unwrap().to_str().unwrap()
            )
            .unwrap();
        }

        writeln!(&mut enclave_edl_file, "}};").unwrap();
    }

    if !edger8.status()?.success() {
        panic!("edger8r did not execute successfully.");
    }

    Ok(())
}

/// Enable SGX features based on current mode.
pub fn detect_sgx_features() {
    let config = get_build_configuration();

    match config.mode {
        SgxMode::Simulation => {
            // Enable sgx-simulation feature.
            println!("cargo:rustc-cfg=feature=\"sgx-simulation\"");
        }
        _ => {}
    }
}

/// Find untrusted libraries to link with and emit their paths to Cargo.
pub fn find_untrusted_libs() {
    let config = get_build_configuration();

    println!(
        "cargo:rustc-link-search=native={}",
        Path::new(&config.intel_sdk_dir)
            .join(SGX_SDK_LIBRARY_PATH)
            .to_str()
            .unwrap()
    );
}

/// Build the untrusted part of an Ekiden enclave.
pub fn build_untrusted(edls: sgx_edl::EDLs) {
    let config = get_build_configuration();

    // Create temporary directory to hold the built libraries.
    let temp_dir = mktemp::Temp::new_dir().expect("Failed to create temporary directory");
    let temp_dir_path = temp_dir.to_path_buf();
    let temp_dir_name = temp_dir_path.to_str().unwrap();

    // Generate proxy for untrusted part.
    edger8r(&config, BuildPart::Untrusted, &temp_dir_name, &edls).expect("Failed to run edger8r");

    // Build proxy.
    let mut builder = cc::Build::new();
    builder
        .file(temp_dir_path.join("enclave_u.c"))
        .flag_if_supported("-m64")
        .flag_if_supported("-O2")  // TODO: Should be based on debug/release builds.
        .flag_if_supported("-fPIC")
        .flag_if_supported("-Wno-attributes");
    for search_path in edls.search_paths.iter() {
        builder.include(search_path);
    }
    builder
        .include(Path::new(&config.intel_sdk_dir).join(SGX_SDK_INCLUDE_PATH))
        .include(&temp_dir_name)
        .compile("enclave_u");

    println!("cargo:rustc-link-lib=static=enclave_u");
    find_untrusted_libs();
}

/// Build the trusted Ekiden SGX enclave.
pub fn build_trusted(edls: sgx_edl::EDLs) {
    let config = get_build_configuration();

    // Create temporary directory to hold the built libraries.
    let temp_dir = mktemp::Temp::new_dir().expect("Failed to create temporary directory");
    let temp_dir_path = temp_dir.to_path_buf();
    let temp_dir_name = temp_dir_path.to_str().unwrap();

    // Generate proxy for trusted part.
    edger8r(&config, BuildPart::Trusted, &temp_dir_name, &edls).expect("Failed to run edger8r");

    // Build proxy.
    let mut builder = cc::Build::new();
    builder
        .file(temp_dir_path.join("enclave_t.c"))
        .flag_if_supported("-m64")
        .flag_if_supported("-O2")  // TODO: Should be based on debug/release builds.
        .flag_if_supported("-nostdinc")
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-fpie")
        .flag_if_supported("-fstack-protector");
    for search_path in edls.search_paths.iter() {
        builder.include(search_path);
    }
    builder
        .include(Path::new(&config.intel_sdk_dir).join(SGX_SDK_INCLUDE_PATH))
        .include(Path::new(&config.intel_sdk_dir).join(SGX_SDK_TLIBC_INCLUDE_PATH))
        .include(Path::new(&config.intel_sdk_dir).join(SGX_SDK_STLPORT_INCLUDE_PATH))
        .include(Path::new(&config.intel_sdk_dir).join(SGX_SDK_EPID_INCLUDE_PATH))
        .include(&temp_dir_name);
    builder.compile("enclave_t");

    println!("cargo:rustc-link-lib=static=enclave_t");
}

/// Generate Rust code for Protocol Buffer messages.
pub fn protoc(args: ProtocArgs) {
    // Run protoc.
    protoc_rust::run(protoc_rust::Args {
        out_dir: args.out_dir,
        includes: args.includes,
        input: args.input,
        customize: protoc_rust::Customize::default(),
    }).expect("Failed to run protoc");

    // Output descriptor of the generated files into a temporary file.
    let temp_dir = mktemp::Temp::new_dir().expect("Failed to create temporary directory");
    let temp_file = temp_dir.to_path_buf().join("descriptor.pbbin");
    let temp_file = temp_file.to_str().expect("utf-8 file name");

    let protoc = super::protoc::Protoc::from_env_path();

    protoc
        .write_descriptor_set(super::protoc::DescriptorSetOutArgs {
            out: temp_file,
            includes: args.includes,
            input: args.input,
            include_imports: true,
        })
        .unwrap();

    let mut fds = Vec::new();
    let mut file = fs::File::open(temp_file).unwrap();
    file.read_to_end(&mut fds).unwrap();

    drop(file);
    drop(temp_dir);

    let fds: protobuf::descriptor::FileDescriptorSet = protobuf::parse_from_bytes(&fds).unwrap();

    // Generate Ekiden-specific impls for all messages.
    for file in fds.get_file() {
        let out_filename = Path::new(&args.out_dir)
            .join(file.get_name())
            .with_extension("rs");
        // Skip protos that we didn't generate, such as those imported from other packages.
        if let Ok(mut out_file) = fs::OpenOptions::new().append(true).open(out_filename) {
            writeln!(&mut out_file, "").unwrap();
            writeln!(&mut out_file, "// Ekiden-specific implementations.").unwrap();

            for message_type in file.get_message_type() {
                writeln!(
                    &mut out_file,
                    "impl_serde_for_protobuf!({});",
                    message_type.get_name()
                ).unwrap();
            }
        }
    }

    // Ensure build script gets re-run in case the output directory is removed.
    println!("cargo:rerun-if-changed={}", args.out_dir);
}

/// Build local enclave API files.
pub fn build_api() {
    protoc(ProtocArgs {
        out_dir: "src/generated/",
        input: &["src/api.proto"],
        includes: &["src/"],
    });
}

/// Generates a module file with specified exported submodules.
pub fn generate_mod(output_dir: &str, modules: &[&str]) {
    generate_mod_with_imports(output_dir, &[], modules)
}

/// Generates a module file with specified imported modules and exported submodules.
pub fn generate_mod_with_imports(output_dir: &str, imports: &[&str], modules: &[&str]) {
    // Create directory if it doesn't exist.
    fs::create_dir_all(output_dir).unwrap();

    // Ensure build script gets re-run in case the output directory is removed.
    println!("cargo:rerun-if-changed={}", output_dir);

    // Create mod.rs
    let output_mod_file = Path::new(&output_dir).join("mod.rs");
    let mut file = fs::File::create(output_mod_file).expect("Failed to create module file");

    for import in imports {
        writeln!(&mut file, "use {};", import).unwrap();
    }

    for module in modules {
        writeln!(&mut file, "pub mod {};", module).unwrap();
    }

    // Create .gitignore
    let output_gitignore_file = Path::new(&output_dir).join(".gitignore");
    let mut file =
        fs::File::create(output_gitignore_file).expect("Failed to create .gitignore file");
    writeln!(&mut file, "*").unwrap();
}

/// Extract enclave identity from a compiled enclave.
pub fn get_enclave_identity<P: AsRef<Path>>(enclave: P) -> Result<Vec<u8>> {
    // Sigstruct headers in bundled enclave.
    let sigstruct_header_1 = Regex::new(
        r"(?-u)\x06\x00\x00\x00\xe1\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00",
    ).unwrap();
    let sigstruct_header_2 = b"\x01\x01\x00\x00\x60\x00\x00\x00\x60\x00\x00\x00\x01\x00\x00\x00";

    let enclave_file = FileBuffer::open(enclave)?;
    let header_1_offset = match sigstruct_header_1.find(&enclave_file) {
        Some(re_match) => re_match.end(),
        None => return Err("Failed to find SIGSTRUCT header 1 in enclave".into()),
    };

    // Skip 8 bytes and expect to find the second header there.
    let header_2_offset = header_1_offset + 8;
    if &enclave_file[header_2_offset..header_2_offset + sigstruct_header_2.len()]
        != sigstruct_header_2
    {
        return Err("Failed to find SIGSTRUCT header 2 in enclave".into());
    }

    // Read ENCLAVEHASH field at offset 920 from second header (32 bytes).
    let hash_offset = header_2_offset + sigstruct_header_2.len() + 920;
    Ok(enclave_file[hash_offset..hash_offset + 32].to_vec())
}

/// Extract enclave identity from a compiled enclave and write it to an output file.
pub fn generate_enclave_identity(output: &str, enclave: &str) {
    let mr_enclave = get_enclave_identity(enclave).expect("Failed to get enclave identity");

    // Write ENCLAVEHASH to given output file.
    let mut output_file = fs::File::create(output).expect("Failed to create output file");
    output_file
        .write_all(&mr_enclave)
        .expect("Failed to write enclave ENCLAVEHASH");

    println!("cargo:rerun-if-changed={}", enclave);
}
