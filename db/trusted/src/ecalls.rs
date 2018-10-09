use std::slice::{from_raw_parts, from_raw_parts_mut};

use ekiden_common::bytes::H256;

use super::{Database, DatabaseHandle};

#[no_mangle]
pub extern "C" fn db_set_root_hash(root_hash: *const u8) {
    let root_hash = H256::from(unsafe { from_raw_parts(root_hash, H256::len()) });
    DatabaseHandle::instance().set_root_hash(root_hash).unwrap();
}

#[no_mangle]
pub extern "C" fn db_commit(root_hash: *mut u8) {
    let dst = unsafe { from_raw_parts_mut(root_hash, H256::len()) };
    let mut db = DatabaseHandle::instance();

    // Commit all pending changes and then get the root hash.
    db.commit().expect("database commit failed");
    dst.clone_from_slice(&db.get_root_hash());
}
