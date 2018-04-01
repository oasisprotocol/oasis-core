pub struct StateInitialized {
    pub checkpoint: Vec<u8>,
    pub checkpoint_height: u64,
    pub diffs: Vec<Vec<u8>>,
}

pub struct State {
    pub everything: Option<StateInitialized>,
}

impl State {
    pub fn new() -> Self {
        State { everything: None }
    }

    pub fn check_tx(_tx: &[u8]) -> Result<(), String> {
        // @todo - check attestations
        // @todo - check that this was based off latest
        Ok(())
    }
}
