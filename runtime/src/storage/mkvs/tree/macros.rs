#[macro_export]
macro_rules! classify_noderef {
    (? $e:expr) => {{
        let kind = match $e {
            None => NodeKind::None,
            Some(ref node) => classify_noderef!(node),
        };
        kind
    }};
    ($e:expr) => {{
        // Ensure references don't leak outside this macro.
        let kind = match *$e.borrow() {
            NodeBox::Internal(_) => NodeKind::Internal,
            NodeBox::Leaf(_) => NodeKind::Leaf,
        };
        kind
    }};
}

#[macro_export]
macro_rules! noderef_as {
    ($ref:expr, $type:ident) => {
        match *$ref.borrow() {
            NodeBox::$type(ref deref) => deref,
            _ => unreachable!(),
        }
    };
}

#[macro_export]
macro_rules! noderef_as_mut {
    ($ref:expr, $type:ident) => {
        match *$ref.borrow_mut() {
            NodeBox::$type(ref mut deref) => deref,
            _ => unreachable!(),
        }
    };
}
