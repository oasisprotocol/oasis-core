//! MRAE primitives.
extern crate aes_soft as aes;
extern crate block_modes;
extern crate crypto_ops;
extern crate ring;
extern crate sodalite;
extern crate zeroize;

use super::error;
use core;

pub mod deoxysii;
pub mod nonce;
pub mod sivaessha2;
