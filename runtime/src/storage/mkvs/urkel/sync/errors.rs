use failure::Fail;

#[derive(Debug, Fail)]
pub enum SyncerError {
    #[fail(display = "urkel: root is dirty")]
    DirtyRoot,
    #[fail(display = "urkel: invalid root")]
    InvalidRoot,
    #[fail(display = "urkel: node not found during sync")]
    NodeNotFound,
    #[fail(display = "urkel: value not found during sync")]
    ValueNotFound,
    #[fail(display = "urkel: method not supported")]
    Unsupported,
}

#[derive(Debug, Fail)]
pub enum SubtreeError {
    #[fail(display = "urkel: too many full nodes")]
    TooManyFullNodes,
    #[fail(display = "urkel: invalid subtree index")]
    InvalidSubtreeIndex,
}
