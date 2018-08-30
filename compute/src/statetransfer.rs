//! Utility for optimistically pulling state from previous committees
use std::result::Result as StdResult;
use std::sync::Arc;

use ekiden_core::futures::prelude::*;
use ekiden_storage_base::StorageBackend;

enum KeyState {
    Present,
    Moved,
    MoveError,
}

#[derive(Debug, Copy, Clone)]
struct KeyStates {
    present: u64,
    moved: u64,
    error: u64,
}

impl KeyStates {
    fn add(&self, state: KeyState) -> KeyStates {
        let mut out = *self;
        match state {
            KeyState::Present => out.present += 1,
            KeyState::Moved => out.moved += 1,
            KeyState::MoveError => out.error += 1,
        };
        out
    }
}

// Task to copy all keys present in the `from` backend not present in the `to` with the same expiry.
pub fn transition_keys(
    from: Arc<StorageBackend>,
    to: Arc<StorageBackend>,
) -> Box<Future<Item = (), Error = ()> + Send> {
    let cached_to = to.clone();
    let f = from.get_keys()
        .map_err(|e| {
            error!("key_transition_fetch_error: {:?}", e);
            measure_counter_inc!("key_transition_fetch_error", 1);
            ()
        })
        .and_then(move |keys| {
            let key_list = keys.clone();
            let cached_to = cached_to.clone();
            let cached_from = from.clone();
            let mut local_keys = vec![];
            for key in key_list.iter() {
                local_keys.push(key.clone());
            }
            let iter = stream::iter_ok::<_, ()>(local_keys.into_iter());

            iter.and_then(
                move |key| -> Box<Future<Item = KeyState, Error = ()> + Send> {
                    let local_to = cached_to.clone();
                    let local_from = cached_from.clone();
                    local_to
                        .get(key.0)
                        .and_then(|_v| future::ok(KeyState::Present))
                        .or_else(move |_e| {
                            local_from
                                .get(key.0)
                                .and_then(move |value| local_to.insert(value, key.1))
                                .then(|res| match res {
                                    Ok(_) => future::ok(KeyState::Moved),
                                    Err(_) => future::ok(KeyState::MoveError),
                                })
                        })
                        .into_box()
                },
            ).fold(
                KeyStates {
                    present: 0,
                    moved: 0,
                    error: 0,
                },
                |states: KeyStates,
                 state: KeyState|
                 -> Box<Future<Item = KeyStates, Error = ()> + Send> {
                    future::ok(states.add(state)).into_box()
                },
            )
        })
        .then(|res: StdResult<KeyStates, ()>| match res {
            Err(e) => {
                error!("key_transition_error: {:?}", e);
                measure_counter_inc!("key_transition_error", 1);
                Ok(())
            }
            Ok(stats) => {
                measure_gauge!("key_transition_present", stats.present);
                measure_gauge!("key_transition_moved", stats.moved);
                measure_gauge!("key_transition_failed", stats.error);
                Ok(())
            }
        });
    Box::new(f)
}
