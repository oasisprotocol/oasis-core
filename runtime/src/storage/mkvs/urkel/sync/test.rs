use std::{any::Any, cell::RefCell, rc::Rc};

use failure::Fallible;
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{marshal::*, sync::*, tree::*},
};

#[test]
fn test_simple() {
    let mut tree = UrkelTree::make()
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    tree.insert(Context::background(), b"foo", b"bar")
        .expect("insert");
    tree.insert(Context::background(), b"moo", b"boo")
        .expect("insert");

    let (_, root) = UrkelTree::commit(&mut tree, Context::background()).expect("commit");

    let st = tree
        .get_subtree(
            Context::background(),
            root,
            NodeID {
                path: root,
                depth: 0,
            },
            10,
        )
        .expect("get_subtree");

    let binary = st.marshal_binary().expect("marshal");
    let mut new_st = Subtree::new();
    new_st.unmarshal_binary(binary.as_ref()).expect("unmarshal");
    assert_eq!(st, new_st);
}

struct DummySerialSyncer {
    backing: Box<dyn ReadSync>,
}

impl ReadSync for DummySerialSyncer {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get_subtree(
        &mut self,
        ctx: Context,
        root_hash: Hash,
        id: NodeID,
        max_depth: u8,
    ) -> Fallible<Subtree> {
        let obj = self.backing.get_subtree(ctx, root_hash, id, max_depth)?;
        let bytes = obj.marshal_binary()?;
        let mut new_st = Subtree::new();
        new_st.unmarshal_binary(bytes.as_ref())?;
        Ok(new_st)
    }

    fn get_path(
        &mut self,
        ctx: Context,
        root_hash: Hash,
        key: Hash,
        start_depth: u8,
    ) -> Fallible<Subtree> {
        let obj = self.backing.get_path(ctx, root_hash, key, start_depth)?;
        let bytes = obj.marshal_binary()?;
        let mut new_st = Subtree::new();
        new_st.unmarshal_binary(bytes.as_ref())?;
        Ok(new_st)
    }

    fn get_node(&mut self, ctx: Context, root_hash: Hash, id: NodeID) -> Fallible<NodeRef> {
        let obj = self.backing.get_node(ctx, root_hash, id)?;
        let bytes = obj.borrow().marshal_binary()?;
        let mut new_node = NodeBox::default();
        new_node.unmarshal_binary(bytes.as_ref())?;
        Ok(Rc::new(RefCell::new(new_node)))
    }

    fn get_value(&mut self, ctx: Context, root_hash: Hash, id: Hash) -> Fallible<Option<Value>> {
        self.backing.get_value(ctx, root_hash, id)
    }
}

#[test]
fn test_nil_pointers() {
    let mut tree = UrkelTree::make()
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    // Arbitrary sequence of operations. The point is to produce a tree with
    // an internal node where at least one of the children is a null pointer.

    tree.insert(Context::background(), b"foo", b"bar")
        .expect("insert");
    tree.insert(Context::background(), b"carrot", b"stick")
        .expect("insert");
    tree.insert(Context::background(), b"ping", b"pong")
        .expect("insert");
    tree.insert(Context::background(), b"moo", b"boo")
        .expect("insert");
    tree.insert(Context::background(), b"aardvark", b"aah")
        .expect("insert");

    // Verify at least one null pointer somewhere.
    //println!("full tree: {:#?}", tree);

    let (_, root) = UrkelTree::commit(&mut tree, Context::background()).expect("commit");

    let wire = DummySerialSyncer {
        backing: Box::new(tree),
    };
    let mut remote = UrkelTree::make()
        .with_root(root)
        .new(Context::background(), Box::new(wire))
        .expect("remote_tree");

    // Now try inserting a k-v pair that will force the tree to traverse through the nil node
    // and dereference it.
    remote
        .insert(Context::background(), b"insert", b"key")
        .expect("insert");
}
