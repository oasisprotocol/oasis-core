use failure::Fail;

#[derive(Debug, Fail)]
pub enum TreeError {
    #[fail(display = "urkel: malformed node")]
    MalformedNode,
    #[fail(display = "urkel: malformed key")]
    MalformedKey,
}
