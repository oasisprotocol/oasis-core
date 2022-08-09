# Building

This section contains a description of steps required to build Oasis Core.
Before proceeding, make sure to look at the [prerequisites] required for running
an Oasis Core environment.

[prerequisites]: prerequisites.md

## Unsafe Non-SGX Environment

To build everything required for running an Oasis node locally, simply execute
the following in the top-level directory:

```
export OASIS_UNSAFE_SKIP_AVR_VERIFY="1"
export OASIS_UNSAFE_SKIP_KM_POLICY="1"
export OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES="1"
make
```

To build BadgerDB without `jemalloc` support (and avoid installing `jemalloc`
on your system), set

```
export OASIS_BADGER_NO_JEMALLOC="1"
```

Not using `jemalloc` is fine for development purposes.

This will build all the required parts (build tools, Oasis node, runtime
libraries, runtime loader, key manager and test runtimes). The AVR and KM flags
are supported on production SGX systems only and these features must be disabled
in our environment.

## SGX Environment

Compilation procedure under SGX environment is similar to the non-SGX with
slightly different environmental variables set:

```
export OASIS_UNSAFE_SKIP_AVR_VERIFY="1"
export OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES="1"
make
```

The AVR flag is there because we are running the node in a local development
environment and we will not do any attestation with Intel's remote servers. The
debug enclaves flag allows enclaves in debug mode to be used.

To run an Oasis node under SGX make sure:

* Your hardware has SGX support.
* You either explicitly enabled SGX in BIOS or made a
  `sgx_cap_enable_device()` system call, if SGX is in software controlled state.
* You installed [Intel's SGX driver] (check that `/dev/isgx` exists).
* You have the AESM daemon running. The easiest way is to just run it in a
  Docker container by doing (this will keep the container running and it will
  be automatically started on boot):

  ```
  docker run \
    --detach \
    --restart always \
    --device /dev/isgx \
    --volume /var/run/aesmd:/var/run/aesmd \
    --name aesmd \
    fortanix/aesmd
  ```

Run `sgx-detect` (part of fortanix rust tools) to verify that everything is
configured correctly.

[Intel's SGX driver]: https://github.com/intel/linux-sgx-driver
