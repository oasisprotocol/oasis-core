use thiserror::Error;

#[derive(Error, Debug)]
pub enum SyncerError {
    #[error("mkvs: method not supported")]
    Unsupported,
}
