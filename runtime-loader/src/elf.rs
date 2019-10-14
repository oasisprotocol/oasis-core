//! ELF runtime loader.
use std::process::Command;

use failure::{format_err, Fallible};

use crate::Loader;

/// ELF runtime loader.
pub struct ElfLoader;

impl Loader for ElfLoader {
    fn run(&self, filename: String, host_socket: String) -> Fallible<()> {
        Command::new(filename)
            .env("OASIS_WORKER_HOST", host_socket)
            .spawn()?
            .wait()
            .map_err(|err| err.into())
            .and_then(|code| {
                if code.success() {
                    Ok(())
                } else {
                    Err(format_err!("process exited: {}", code))
                }
            })
    }
}
