# Enabling backtrace in an enclave
```rust
std::backtrace::enable_backtrace("xxx", std::backtrace::PrintFormat::Short).expect("Failed to enable backtrace");
```

Call [`enable_backtrace`](https://github.com/baidu/rust-sgx-sdk/blob/master/sgx_tstd/src/backtrace.rs#L40-L48) with the path of your enclave's file image (`xxx` above).
