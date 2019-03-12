//! Utilities for working with SGXS enclave format.
use std::{
    env,
    fs::File,
    io::{Result as IoResult, Write},
    path::Path,
    str::FromStr,
};

use failure::{Fallible, ResultExt};
use fortanix_sgxs::sgxs::{copy_measured, SgxsRead};
use ring::digest;

// NOTE: This could use impl_bytes! macro, but this would require depending on
//       ekiden-runtime which is undesirable.

/// An enclave hash (also called MRENCLAVE).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnclaveHash(pub [u8; 32]);

impl AsRef<[u8]> for EnclaveHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ::core::fmt::LowerHex for EnclaveHash {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        for i in &self.0[..] {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

impl ::core::fmt::Debug for EnclaveHash {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::LowerHex::fmt(self, f)
    }
}

impl ::core::fmt::Display for EnclaveHash {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        for i in &self.0[0..2] {
            write!(f, "{:02x}", i)?;
        }
        write!(f, "…")?;
        for i in &self.0[32 - 2..32] {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

impl ::std::str::FromStr for EnclaveHash {
    type Err = ::rustc_hex::FromHexError;

    fn from_str(s: &str) -> Result<EnclaveHash, ::rustc_hex::FromHexError> {
        use ::rustc_hex::FromHex;

        let a: Vec<u8> = s.from_hex()?;
        if a.len() != 32 {
            return Err(::rustc_hex::FromHexError::InvalidHexLength);
        }

        let mut ret = [0; 32];
        ret.copy_from_slice(&a);
        Ok(EnclaveHash(ret))
    }
}

impl EnclaveHash {
    pub fn from_stream<R: SgxsRead>(stream: &mut R) -> Fallible<Self> {
        struct WriteToHasher(digest::Context);

        impl Write for WriteToHasher {
            fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
                self.0.update(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> IoResult<()> {
                Ok(())
            }
        }

        let mut out = WriteToHasher(digest::Context::new(&digest::SHA256));
        copy_measured(stream, &mut out)?;

        let mut result = [0u8; 32];
        result[..].copy_from_slice(out.0.finish().as_ref());

        Ok(EnclaveHash(result))
    }
}

/// Compute enclave hash of the given SGXS file.
pub fn get_enclave_hash<P: AsRef<Path>>(path: P) -> Fallible<EnclaveHash> {
    let mut file = File::open(path)?;
    EnclaveHash::from_stream(&mut file)
}

/// Generate enclave hash for use in build scripts.
///
/// The generated file will be put into `<OUT_DIR>/<prefix>_enclave_hash.rs`
/// and can be included using:
/// ```rust,ignore
/// include!(concat!(env!("OUT_DIR"), "/<prefix>_enclave_hash.rs"));
/// ```
pub fn generate_enclave_hash(prefix: &str, description: &str) -> Fallible<()> {
    let out_dir = env::var("OUT_DIR").unwrap();
    let env_enclave_hash = format!("{}_ENCLAVE_HASH", prefix.to_uppercase());
    let env_enclave_path = format!("{}_ENCLAVE_PATH", prefix.to_uppercase());

    println!("cargo:rerun-if-env-changed={}", env_enclave_hash);
    println!("cargo:rerun-if-env-changed={}", env_enclave_path);

    // Generate the key manager enclave identity.
    let mut enclave_hash = env::var(&env_enclave_hash);
    if enclave_hash.is_err() {
        let enclave_path = env::var(&env_enclave_path).context(format!(
            "please define {} or {}",
            env_enclave_hash, env_enclave_path
        ))?;
        println!("cargo:rerun-if-changed={}", enclave_path);

        let hash = get_enclave_hash(enclave_path).context("failed to compute enclave hash")?;
        enclave_hash = Ok(format!("{:?}", hash));
    }

    let enclave_hash = EnclaveHash::from_str(&enclave_hash.unwrap())?;

    let dest_path = Path::new(&out_dir).join(format!("{}_enclave_hash.rs", prefix.to_lowercase()));
    let mut f = File::create(&dest_path)?;

    f.write_all(
        format!(
            "
        use ::ekiden_runtime::common::sgx::avr::MrEnclave;

        /// {} enclave hash ({:?}).
        pub const {}_ENCLAVE_HASH: MrEnclave = MrEnclave({:?});
    ",
            description,
            enclave_hash,
            prefix.to_uppercase(),
            enclave_hash.0,
        )
        .as_bytes(),
    )?;

    Ok(())
}
