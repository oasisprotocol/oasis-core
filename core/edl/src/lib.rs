#[macro_use]
extern crate ekiden_tools;

extern crate ekiden_db_edl;
extern crate ekiden_enclave_edl;
extern crate ekiden_rpc_edl;
extern crate sgx_edl;

define_edl! {
    use sgx_edl;
    use ekiden_enclave_edl;
    use ekiden_rpc_edl;
    use ekiden_db_edl;

    "core.edl",
}
