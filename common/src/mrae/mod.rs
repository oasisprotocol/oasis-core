//! SIV_CTR-AES128_HMAC-SHA256-128 MRAE primitives.
extern crate aes_soft as aes;
extern crate block_modes;
extern crate crypto_ops;
extern crate ring;
extern crate sodalite;

use super::error;

pub mod sivaessha2;
