//! Cargo-specific structures.
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use toml;

use ekiden_common::error::{Error, Result};

/// Abstract crate source.
pub trait CrateSource {
    /// Write a Cargo-compatible dependency spec to a given writer. Includes newline.
    fn write_location(&self, writer: &mut Write) -> Result<()>;
}

/// Git crate source.
#[derive(Debug)]
pub struct GitSource<'a> {
    pub repository: &'a str,
    pub branch: Option<&'a str>,
    pub tag: Option<&'a str>,
    pub rev: Option<&'a str>,
}

impl<'a> CrateSource for GitSource<'a> {
    fn write_location(&self, mut writer: &mut Write) -> Result<()> {
        write!(&mut writer, "{{ git = \"{}\"", self.repository)?;

        if let Some(ref branch) = self.branch {
            write!(&mut writer, ", branch = \"{}\"", branch)?;
        } else if let Some(ref tag) = self.tag {
            write!(&mut writer, ", tag = \"{}\"", tag)?;
        } else if let Some(ref rev) = self.rev {
            write!(&mut writer, ", rev = \"{}\"", rev)?;
        }

        writeln!(&mut writer, " }}")?;

        Ok(())
    }
}

/// Crates.io version crate source.
#[derive(Debug)]
pub struct VersionSource<'a> {
    pub version: &'a str,
}

impl<'a> CrateSource for VersionSource<'a> {
    fn write_location(&self, mut writer: &mut Write) -> Result<()> {
        writeln!(&mut writer, "\"{}\"", self.version)?;

        Ok(())
    }
}

/// Local path crate source.
#[derive(Debug)]
pub struct PathSource {
    pub path: PathBuf,
}

impl CrateSource for PathSource {
    fn write_location(&self, mut writer: &mut Write) -> Result<()> {
        writeln!(
            &mut writer,
            "{{ path = \"{}\" }}",
            self.path.to_str().unwrap()
        )?;

        Ok(())
    }
}

/// Cargo package metadata.
#[derive(Deserialize, Debug)]
pub struct Package {
    pub name: String,
    pub version: String,
}

/// Cargo workspace metadata.
#[derive(Deserialize, Debug)]
pub struct Workspace {
    members: Vec<String>,
}

/// Cargo manifest.
#[derive(Deserialize, Debug)]
pub struct Manifest {
    package: Option<Package>,
    workspace: Option<Workspace>,
}

/// Cargo project root.
#[derive(Debug)]
pub struct ProjectRoot {
    /// Path to the project root (directory containing Cargo.toml).
    path: PathBuf,
    /// Path to the workspace root.
    workspace_path: PathBuf,
    /// Parsed configuration file.
    manifest: Manifest,
}

impl ProjectRoot {
    /// Attempts to discover the root of the current project.
    pub fn discover() -> Result<Self> {
        // Start with the current directory and recursively move up if Cargo.toml
        // cannot be found in the given directory.
        let mut current_dir: &Path = &env::current_dir()?;
        loop {
            if current_dir.join("Cargo.toml").exists() {
                return Ok(ProjectRoot::new(current_dir.to_owned())?);
            }

            if let Some(parent) = current_dir.parent() {
                current_dir = parent;
            } else {
                // We've reached the root.
                return Err(Error::new("failed to discover project root"));
            }
        }
    }

    /// Parse Cargo manifest file.
    fn parse_manifest<P: AsRef<Path>>(path: P) -> Result<Manifest> {
        // Parse configuration file.
        let mut data = String::new();
        File::open(path)?.read_to_string(&mut data)?;

        Ok(toml::from_str(&data)?)
    }

    /// Create new project root.
    pub fn new(path: PathBuf) -> Result<Self> {
        let manifest = Self::parse_manifest(path.join("Cargo.toml"))?;
        let workspace_path = if manifest.workspace.is_some() {
            // This is already a workspace.
            path.clone()
        } else {
            // Discover the workspace.
            let mut current_dir: &Path = &path;
            loop {
                let manifest_path = current_dir.join("Cargo.toml");
                if manifest_path.exists() {
                    let workspace_manifest = Self::parse_manifest(&manifest_path)?;
                    match workspace_manifest.workspace {
                        Some(ref workspace) => {
                            // Contains a workspace. Ensure that this workspace also contains
                            // the project root.
                            if !workspace
                                .members
                                .iter()
                                .any(|m| current_dir.join(m) == path)
                            {
                                return Err(Error::new(format!(
                                    "current package believes it's in a workspace when it's not: \n\
                                    current:   {}\n\
                                    workspace: {}\n\
                                    \n\
                                    this may be fixable by adding `{}` to the \
                                    `workspace.members` array of the manifest located at: {}",
                                    path.join("Cargo.toml").to_str().unwrap(),
                                    current_dir.to_str().unwrap(),
                                    path.strip_prefix(current_dir).unwrap().to_str().unwrap(),
                                    manifest_path.to_str().unwrap()
                                )));
                            }

                            break current_dir.to_owned();
                        }
                        None => {}
                    }
                }

                if let Some(parent) = current_dir.parent() {
                    current_dir = parent;
                } else {
                    // We've reached the root, project is its own workspace.
                    break path.clone();
                }
            }
        };

        Ok(ProjectRoot {
            path,
            workspace_path,
            manifest,
        })
    }

    pub fn get_path(&self) -> PathBuf {
        self.path.clone()
    }

    pub fn get_workspace_path(&self) -> PathBuf {
        self.workspace_path.clone()
    }

    /// Get project config path (Cargo.toml).
    pub fn get_config_path(&self) -> PathBuf {
        self.path.join("Cargo.toml")
    }

    /// Get project target directory path.
    pub fn get_target_path(&self) -> PathBuf {
        if let Ok(path) = env::var("CARGO_TARGET_DIR") {
            Path::new(&path).to_owned()
        } else {
            self.workspace_path.join("target")
        }
    }

    /// Parse project config (Cargo.toml).
    pub fn get_config(&self) -> &Manifest {
        &self.manifest
    }

    /// Check if given project contains a package.
    pub fn is_package(&self) -> bool {
        self.manifest.package.is_some()
    }

    /// Check if given project contains a workspace.
    pub fn is_workspace(&self) -> bool {
        self.manifest.workspace.is_some()
    }

    /// Get package metadata.
    pub fn get_package(&self) -> Option<&Package> {
        self.manifest.package.as_ref()
    }

    /// Get workspace metadata.
    pub fn get_workspace(&self) -> Option<&Workspace> {
        self.manifest.workspace.as_ref()
    }
}
