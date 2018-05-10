use std::slice::{from_raw_parts, from_raw_parts_mut};

use ekiden_common::bytes::H256;

use super::handle::DatabaseHandle;

#[no_mangle]
pub extern "C" fn db_set_root_hash(root_hash: *const u8) {
    let root_hash = H256::from(unsafe { from_raw_parts(root_hash, H256::len()) });
    DatabaseHandle::instance().set_root_hash(root_hash).unwrap();
}

#[no_mangle]
pub extern "C" fn db_get_root_hash(root_hash: *mut u8) {
    let dst = unsafe { from_raw_parts_mut(root_hash, H256::len()) };
    dst.clone_from_slice(&DatabaseHandle::instance().get_root_hash().unwrap());
}
