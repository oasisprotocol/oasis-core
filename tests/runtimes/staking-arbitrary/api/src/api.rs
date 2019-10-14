use oasis_core_runtime::{common::crypto::signature::PublicKey, runtime_api};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AccountAmount {
    pub account: PublicKey,
    pub amount: Vec<u8>,
}

runtime_api! {
    pub fn increase(AccountAmount) -> ();
    pub fn decrease(AccountAmount) -> ();
}
