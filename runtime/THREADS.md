# Threads

The following **8 threads** are used by the runtime:

* 2 runtime host protocol I/O threads.
* 1 consensus verifier thread.
* 1 dispatcher main loop thread.
* 2 dispatcher worker threads.
* 2 dispatcher processing threads.

This must be taken into account when building the runtime for SGX as all the
thread control structures (TCS) must be defined in advance.
