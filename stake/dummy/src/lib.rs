//! Ekiden dummy registry backend.
extern crate ekiden_common;
extern crate ekiden_stake_api;
extern crate ekiden_stake_base;
extern crate serde;
extern crate serde_cbor;

mod stake;

pub use stake::DummyStakeEscrowBackend;
pub use stake::LittleEndianCounter32;  // test uses this too to be deterministic
pub use stake::INTERNAL_ERROR;
pub use stake::NO_STAKE_ACCOUNT;
pub use stake::NO_ESCROW_ACCOUNT;
pub use stake::WOULD_OVERFLOW;
pub use stake::INSUFFICIENT_FUNDS;
pub use stake::REQUEST_EXCEEDS_ESCROWED;

