use failure::Fail;

#[derive(Debug, Fail)]
pub enum TreeError {
    #[fail(display = "mkvs: malformed node")]
    MalformedNode,
    #[fail(display = "mkvs: malformed key")]
    MalformedKey,
}
