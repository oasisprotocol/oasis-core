/// Wrapper for log::Record used for serialization/deserialization
///
/// Actual serialization is implemented in ekiden_enclave_trusted::EkidenLogger::log()
/// and deserialization in ekiden_enclave_untrusted::untrusted_log().
#[derive(Serialize, Deserialize, Debug)]
pub struct EkidenLoggerRecord<'a> {
    pub metadata_level: log::Level,
    pub metadata_target: &'a str,
    pub args: String,
    pub module_path: Option<&'a str>,
    pub file: Option<&'a str>,
    pub line: Option<u32>,
}
