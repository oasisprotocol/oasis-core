use io_context::Context;

use crate::storage::mkvs::{
    urkel::{
        interop::{Driver, ProtocolServer},
        sync::*,
        tree::*,
    },
    LogEntry,
};

#[test]
fn test_nil_pointers() {
    let server = ProtocolServer::new();

    let mut tree = UrkelTree::make()
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    // Arbitrary sequence of operations. The point is to produce a tree with
    // an internal node where at least one of the children is a null pointer.

    let write_log = vec![
        LogEntry::new(b"foo", b"bar"),
        LogEntry::new(b"carrot", b"stick"),
        LogEntry::new(b"ping", b"pong"),
        LogEntry::new(b"moo", b"boo"),
        LogEntry::new(b"aardvark", b"aah"),
    ];

    for entry in write_log.iter() {
        tree.insert(Context::background(), &entry.key, &entry.value)
            .expect("insert");
    }

    // Verify at least one null pointer somewhere.
    //println!("full tree: {:#?}", tree);

    let (_, root) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");

    server.apply(&write_log, root, Default::default(), 0);

    let mut remote = UrkelTree::make()
        .with_root(Root {
            hash: root,
            ..Default::default()
        })
        .new(Context::background(), server.read_sync())
        .expect("remote_tree");

    // Now try inserting a k-v pair that will force the tree to traverse through the nil node
    // and dereference it.
    remote
        .insert(Context::background(), b"insert", b"key")
        .expect("insert");
}
