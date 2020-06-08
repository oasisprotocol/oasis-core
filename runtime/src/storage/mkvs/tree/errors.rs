use thiserror::Error;

#[derive(Error, Debug)]
pub enum TreeError {
    #[error("mkvs: malformed node")]
    MalformedNode,
    #[error("mkvs: malformed key")]
    MalformedKey,
}
