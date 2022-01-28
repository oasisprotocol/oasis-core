//! Simplified cargo structures.
//!
//! These are used to avoid pulling in cargo as a dependency, but
//! they may not be exactly consistent with what cargo does.
use std::{
    env,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use serde::Deserialize;
use toml;

/// Fortanix SGX metadata (based on ftxsgx-runner-cargo).
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct FortanixSGX {
    pub heap_size: Option<u64>,
    pub ssaframesize: Option<u32>,
    pub stack_size: Option<u32>,
    pub threads: Option<u32>,
    pub debug: Option<bool>,
}

/// Cargo package metadata.
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Metadata {
    #[serde(default)]
    pub fortanix_sgx: FortanixSGX,
}

/// Cargo binary target.
#[derive(Deserialize, Debug)]
pub struct Binary {
    pub name: String,
}

/// Cargo package.
#[derive(Deserialize, Debug)]
pub struct Package {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub metadata: Metadata,
}

/// Cargo workspace.
#[derive(Deserialize, Debug)]
pub struct Workspace {
    members: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}

/// Cargo manifest.
#[derive(Deserialize, Debug)]
pub struct Manifest {
    package: Option<Package>,
    workspace: Option<Workspace>,
    bin: Option<Vec<Binary>>,
}

/// Cargo package root.
#[derive(Debug)]
pub struct PackageRoot {
    /// Path to the package root.
    path: PathBuf,
    /// Path to the workspace root.
    workspace_path: PathBuf,
    /// Parsed manifest.
    manifest: Manifest,
}

impl PackageRoot {
    /// Attempts to discover the root of the current package.
    pub fn discover() -> Result<Self> {
        // Start with the current directory and recursively move up if Cargo.toml
        // cannot be found in the given directory.
        let mut current_dir: &Path = &env::current_dir()?;
        loop {
            if current_dir.join("Cargo.toml").exists() {
                return PackageRoot::new(current_dir.to_owned());
            }

            if let Some(parent) = current_dir.parent() {
                current_dir = parent;
            } else {
                // We've reached the root.
                return Err(anyhow!("failed to discover package root"));
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
                    if let Some(ref workspace) = workspace_manifest.workspace {
                        // Contains a workspace. Check if the package root is excluded.
                        if workspace
                            .exclude
                            .iter()
                            .any(|m| path.starts_with(current_dir.join(m)))
                        {
                            // Package root is excluded, so the package is its own workspace.
                            break path.clone();
                        }

                        // If not excluded, ensure that this workspace also contains
                        // the package root.
                        if !workspace
                            .members
                            .iter()
                            .any(|m| path.starts_with(current_dir.join(m)))
                        {
                            return Err(anyhow!(
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
                            ));
                        }

                        break current_dir.to_owned();
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

        Ok(PackageRoot {
            path,
            workspace_path,
            manifest,
        })
    }

    /// Path to package root.
    pub fn package_path(&self) -> PathBuf {
        self.path.clone()
    }

    /// Path to workspace root.
    pub fn workspace_path(&self) -> PathBuf {
        self.workspace_path.clone()
    }

    /// Path to package manifest.
    pub fn manifest_path(&self) -> PathBuf {
        self.path.join("Cargo.toml")
    }

    /// Path to package target directory.
    pub fn target_path(&self) -> PathBuf {
        if let Ok(path) = env::var("CARGO_TARGET_DIR") {
            Path::new(&path).to_owned()
        } else {
            self.workspace_path.join("target")
        }
    }

    /// Parsed package manifest.
    pub fn manifest(&self) -> &Manifest {
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
    pub fn package(&self) -> Option<&Package> {
        self.manifest.package.as_ref()
    }

    /// Get workspace metadata.
    pub fn workspace(&self) -> Option<&Workspace> {
        self.manifest.workspace.as_ref()
    }

    /// Get the target names specified in the package metadata.
    pub fn target_names(&self) -> Vec<String> {
        let mut targets: Vec<String> = Vec::new();
        if let Some(ref bin) = self.manifest.bin {
            for bin in bin {
                targets.push(String::from(&bin.name));
            }
        } else if let Some(package) = self.package() {
            targets.push(String::from(&package.name));
        }
        targets
    }
}
