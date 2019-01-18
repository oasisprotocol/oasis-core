# Profiling

## Non-SGX

To profile non-SGX portions of Ekiden, you can use standard tools like `valgrind`. Note that there
is a bug in older Valgrind versions, which makes it incorrectly advertise RDRAND support in CPUID
and when it is used it crashes with an illegal instruction error. For this reason be sure to use
Valgrind version 3.13 or greater which is known to work.

After installing Valgrind, you can use it as normal (e.g., for profiling the compute node):
```bash
$ valgrind \
    --tool=callgrind \
    --callgrind-out-file=callgrind.out \
    target/debug/ekiden-compute target/enclave/simple-keyvalue.so
```

After the program terminates (you can interrupt it using CTRL+C), you can run the annotate tool
to get a human-readable report:
```bash
$ callgrind_annotate callgrind.out
```

## SGX

### Setting up the environment
1. host: install SGX driver
1. host: install vtune, including collection driver
1. make /code available on host for vtune
   (you can symlink it)
   (todo: any better ways to do this?)
1. make /opt/intel/vtune_amplifier_2018.1.0.535340 available in the container for runtime libs
   (you can do this with a volume mount, but it's not built in to scripts/sgx-enter-hw.sh)
   (see 19389292a4ecf889ba8a4ed20d1b58d9f3156f8e for how to undo this)
1. host: set /proc/sys/kernel/yama/ptrace_scope to 0
   (setup recommends, but we have to profile as superuser anyway)

### Building the project
1. container: `export SGX_MODE=HW`
   (scripts/sgx-enter-hw.sh sets this)
1. add `-C opt-level=3` to `RUSTFLAGS` in `tasks.env-debug.env` and `tasks.env-sgx-xargo` in Makefile.toml
   (see d826188ca5232cb9b342a46ebe67a90db2726afe for how to undo this)
1. container: `cargo make`

### Collecting a profile
1. start container
1. container: `export INTEL_LIBITTNOTIFY64=/opt/intel/vtune_amplifier_2018.1.0.535340/lib64/runtime/libittnotify_collector.so`
   (adapted from https://software.intel.com/en-us/node/708952)
1. container: `. scripts/start-aesmd.sh`
   (source, it creates a background job)
   (requires privileged container, or it can't access the sgx service)
   (scripts/sgx-enter-hw.sh runs the container privileged)
   (todo: privileged container is undesirable for production)
1. container: start nodes without batch timeout
1. host: `sudo su`
1. host, as superuser: `. /opt/intel/vtune_amplifier_2018.1.0.535340/amplxe-vars.sh`
1. host, as superuser: `amplxe-cl -collect advanced-hotspots -duration=60 -analyze-system`
   (specifying a `-target-pid` in a container freezes docker)
   (using sgx-hotspots analysis causes kernel oops)
1. container: `./target/debug/my-client --mr-enclave $(cat target/enclave/my.mrenclave) --benchmark-threads=1 --benchmark-runs=10`
1. host, as superuser: ctrl-c ampxle-cl
1. host, as superuser: `amplxe-cl -finalize -r rxxxah`
1. host: `ampxle-cl -report hotspots -r rxxxah`
