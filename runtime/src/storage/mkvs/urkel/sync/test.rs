use crate::storage::mkvs::urkel::{marshal::*, sync::*, tree::*};

#[test]
fn test_simple() {
    let mut tree = UrkelTree::make()
        .new(Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    tree.insert(b"foo", b"bar").expect("insert");
    tree.insert(b"moo", b"boo").expect("insert");

    let (_, root) = UrkelTree::commit(&mut tree).expect("commit");

    let st = tree
        .get_subtree(
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
