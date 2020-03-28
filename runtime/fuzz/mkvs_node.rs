use honggfuzz::fuzz;

use oasis_core_runtime::storage::mkvs::{marshal::Marshal, NodeBox};

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            let mut node = NodeBox::default();
            if node.unmarshal_binary(data).is_err() {
                return;
            }

            let _ = node.marshal_binary().unwrap();
        });
    }
}
