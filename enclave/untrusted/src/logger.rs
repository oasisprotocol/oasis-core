use ekiden_enclave_common::logger::EkidenLoggerRecord;
use ekiden_enclave_common::utils::read_enclave_request;

/// Deserializes EkidenLoggerRecord and relays it to log::logger().log().
#[cfg(not(target_env = "sgx"))]
#[no_mangle]
pub extern "C" fn untrusted_log(record: *const u8, record_length: usize) {
    let r: EkidenLoggerRecord = read_enclave_request(record, record_length);

    let tgt: String = match r.metadata_target {
        "" => format!("<enclave>"),
        _ => format!("<enclave>::{}", r.metadata_target),
    };
    log::logger().log(&log::Record::builder()
        .metadata(
            log::MetadataBuilder::new()
                .target(tgt.as_str())
                .level(r.metadata_level)
                .build(),
        )
        .args(format_args!("{}", r.args))
        .line(r.line)
        .file(r.file)
        .module_path(r.module_path)
        .build());
}
