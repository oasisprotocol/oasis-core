extern crate sgx_edl;
use sgx_edl::define_edl;

extern crate ekiden_edl;

define_edl! {
    use ekiden_edl;

    "keymanager.edl"
}
