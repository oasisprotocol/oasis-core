#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("shareholder encoding failed")]
    ShareholderEncodingFailed,
    #[error("zero value shareholder")]
    ZeroValueShareholder,
}
