use ekiden_core::runtime::runtime_api;

runtime_api! {
    pub fn write_error(String) -> ();
    pub fn write_warn(String)  -> ();
    pub fn write_info(String)  -> ();
    pub fn write_debug(String) -> ();
    pub fn write_trace(String) -> ();
}
