use failure::Fail;

#[derive(Debug, Fail)]
pub enum SyncerError {
    #[fail(display = "mkvs: method not supported")]
    Unsupported,
}
