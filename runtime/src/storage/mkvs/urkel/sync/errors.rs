use failure::Fail;

#[derive(Debug, Fail)]
pub enum SyncerError {
    #[fail(display = "urkel: method not supported")]
    Unsupported,
}
