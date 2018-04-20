//! Tool subcommand for entering contract environment.
extern crate clap;
extern crate ekiden_common;

use self::clap::ArgMatches;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::process::{Child, Command};

use super::cargo;

use ekiden_common::error::{Error, Result};

/// Determine if a given docker image is available.
fn docker_has(args: Vec<&str>) -> Result<()> {
    match Command::new("docker").args(args).output()?.stdout.len() {
        0 => Err(Error::new("No result")),
        _ => Ok(()),
    }
}

/// Execute a shell in a given container.
fn docker_exec(container: &str, escape_keys: &str, shell: &str) -> Result<Child> {
    Ok(Command::new("docker")
        .args(&[
            "exec",
            "-i",
            "-t",
            "--detach-keys",
            escape_keys,
            container,
            "/usr/bin/env",
            shell,
        ])
        .spawn()?)
}

/// Start a specific docker image.
fn docker_create(
    container: &str,
    location: &str,
    image: &str,
    escape_keys: &str,
    shell: &str,
    hw: bool,
) -> Result<Child> {
    let mut args = vec![
        "run",
        "-i",
        "-t",
        "--name",
        container,
        "-v",
        location,
        "-e",
        if hw { "SGX_MODE=HW" } else { "SGX_MODE=SIM" },
        "-e",
        "INTEL_SGX_SDK=/opt/sgxsdk",
        "-w",
        "/code",
        "--detach-keys",
        escape_keys,
        image,
        "/usr/bin/env",
        shell,
    ];
    if hw {
        args.insert(3, "--privileged");
    } else {
        args.insert(3, "-e");
        args.insert(4, "EKIDEN_UNSAFE_SKIP_AVR_VERIFY=1");
    }
    Ok(Command::new("docker").args(args.iter()).spawn()?)
}

/// Generate a container name from the project, along with a hash of path+sgxmode.
fn container_default_name(project: &cargo::ProjectRoot, hardware: bool) -> String {
    let package_name = match project.get_package() {
        Some(package) => package.name.clone(),
        None => String::from("ekiden"),
    };
    let work_dir = project.get_workspace_path();
    let work_dir = work_dir.to_str().unwrap();
    let mut s = DefaultHasher::new();
    work_dir.hash(&mut s);

    let mut sgx = "";
    if hardware {
        sgx = "-sgx";
    }
    let hash = s.finish();
    format!("{}-{}{}", package_name, format!("{:x}", hash), sgx)
}

/// Enter an Ekiden environment.
pub fn shell(args: &ArgMatches) -> Result<()> {
    let project = cargo::ProjectRoot::discover()?;

    let work_dir = project.get_workspace_path();
    let work_dir = work_dir.to_str().unwrap();

    // Container name defaults to a basename of the current work dir.
    let container_name = container_default_name(&project, args.is_present("hardware"));
    let container_name = match args.value_of("docker-name") {
        Some(name) => String::from(name),
        None => container_name,
    };

    // Make sure docker exists.
    if let Err(_err) = Command::new("docker").arg("version").output() {
        return Err(Error::new("Please install Docker to use Ekiden shell"));
    }

    // Enter running environment.
    let child = match docker_has(vec![
        "ps",
        "-q",
        "-f",
        ("name=".to_owned() + &container_name).as_str(),
    ]) {
        Ok(_) => docker_exec(
            &container_name,
            args.value_of("detach-keys").unwrap(),
            args.value_of("docker-shell").unwrap(),
        ),
        _ => match docker_has(vec![
            "ps",
            "-aq",
            "-f",
            ("name=".to_owned() + &container_name).as_str(),
        ]) {
            Ok(_) => {
                Command::new("docker")
                    .args(&["start", &container_name])
                    .status()?;
                docker_exec(
                    &container_name,
                    args.value_of("detach-keys").unwrap(),
                    args.value_of("docker-shell").unwrap(),
                )
            }
            _ => docker_create(
                &container_name,
                (work_dir.to_owned() + ":/code").as_str(),
                args.value_of("docker-image").unwrap(),
                args.value_of("detach-keys").unwrap(),
                args.value_of("docker-shell").unwrap(),
                args.is_present("hardware"),
            ),
        },
    };

    child?.wait()?;
    Ok(())
}

/// Remove an Ekiden environment.
pub fn cleanup_shell(args: &ArgMatches) -> Result<()> {
    let project = cargo::ProjectRoot::discover()?;

    // Container name defaults to a basename of the current work dir.
    let container_name = container_default_name(&project, args.is_present("hardware"));
    let container_name = match args.value_of("docker-name") {
        Some(name) => String::from(name),
        None => container_name,
    };

    Command::new("docker")
        .args(&["rm", "-f", &container_name])
        .status()?;
    Ok(())
}
