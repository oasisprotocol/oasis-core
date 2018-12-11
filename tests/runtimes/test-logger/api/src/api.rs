use ekiden_core::runtime::runtime_api;

runtime_api! {
    pub fn init() -> Result<LoggerInitResponse>;
    pub fn write_error(&str) -> ();
    pub fn write_warn(&str)  -> ();
    pub fn write_info(&str)  -> ();
    pub fn write_debug(&str) -> ();
    pub fn write_trace(&str) -> ();
}
