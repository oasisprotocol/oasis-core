# Local Network Runner

In order to make development easier (and also to facilitate automated E2E
tests), the Oasis Core repository provides a utility called `oasis-net-runner`
that enables developers to quickly set up local networks.

Before proceeding, make sure to look at the [prerequisites] required for running
an Oasis Core environment followed by [build instructions] for the respective
environment (non-SGX or SGX). The following sections assume that you have
successfully completed the required build steps.

[prerequisites]: prerequisites.md
[build instructions]: building.md

## Unsafe Non-SGX Environment

To start a simple Oasis network as defined by [the default network fixture]
running the `simple-keyvalue` test runtime, do:

```
./go/oasis-net-runner/oasis-net-runner \
  --fixture.default.node.binary go/oasis-node/oasis-node \
  --fixture.default.runtime.binary target/default/debug/simple-keyvalue \
  --fixture.default.runtime.loader target/default/debug/oasis-core-runtime-loader \
  --fixture.default.keymanager.binary target/default/debug/simple-keymanager
```

Wait for the network to start, there should be messages about nodes being
started and at the end the following message should appear:

<!-- markdownlint-disable line-length -->
```
level=info module=oasis/net-runner caller=oasis.go:319 ts=2019-10-03T10:47:30.776566482Z msg="network started"
level=info module=net-runner caller=root.go:145 ts=2019-10-03T10:47:30.77662061Z msg="client node socket available" path=/tmp/oasis-net-runner530668299/net-runner/network/client-0/internal.sock
```
<!-- markdownlint-enable line-length -->

The `simple-keyvalue` runtime implements a key-value hash map in the enclave
and supports reading, writing, and fetching string values associated with the
given key. To learn how to create your own runtime, see the sources of the
[simple-keyvalue example] and [Building a runtime] chapter in the Oasis SDK.

Finally, to test Oasis node, we will run a test client written specifically
for the `simple-keyvalue` runtime. The client sends a few keys with associated
values and fetches them back over RPC defined in the runtime's API. Execute the
client as follows (substituting the socket path from your log output) in a
different terminal:

```
./target/default/debug/simple-keyvalue-client \
  --runtime-id 8000000000000000000000000000000000000000000000000000000000000000 \
  --node-address unix:/tmp/oasis-net-runner530668299/net-runner/network/client-0/internal.sock
```

By default, Oasis node is configured with a 30-second epoch, so you may
initially need to wait for the first epoch to pass before the test client will
make any progress. For more information on writing your own client, see the
[Oasis SDK](https://github.com/oasisprotocol/oasis-sdk).

<!-- markdownlint-disable line-length -->
[the default network fixture]: https://github.com/oasisprotocol/oasis-core/tree/master/go/oasis-net-runner/fixtures/default.go
[simple-keyvalue example]: https://github.com/oasisprotocol/oasis-core/tree/master/tests/runtimes/simple-keyvalue
[Building a runtime]: https://github.com/oasisprotocol/oasis-sdk/blob/main/docs/runtime/README.md
<!-- markdownlint-enable line-length -->

## SGX Environment

To run an Oasis node under SGX follow the same steps as for non-SGX, except the
`oasis-net-runner` invocation:

<!-- markdownlint-disable line-length -->
```
./go/oasis-net-runner/oasis-net-runner \
  --fixture.default.tee_hardware intel-sgx \
  --fixture.default.node.binary go/oasis-node/oasis-node \
  --fixture.default.runtime.binary target/sgx/x86_64-fortanix-unknown-sgx/debug/simple-keyvalue.sgxs \
  --fixture.default.runtime.loader target/default/debug/oasis-core-runtime-loader \
  --fixture.default.keymanager.binary target/sgx/x86_64-fortanix-unknown-sgx/debug/simple-keymanager.sgxs
```
<!-- markdownlint-enable line-length -->

## Common Issues

If the above does not appear to work (e.g., when you run the client, it appears
to hang and not make any progress) usually the best place to start debugging is
looking at the various node logs which are stored under a directory starting
with `/tmp/oasis-net-runner` (unless overriden via `--basedir` options).

Specifically look at `node.log` and `console.log` files located in directories
for each of the nodes comprising the local network.

### User Namespace Permission Issues

The Oasis Core compute nodes use [sandboxing] to execute runtime binaries and
the sandbox implementation requires that the process is able to create
non-privileged user namespaces.

In case this is not available, the following error message may appear in
`console.log` of any compute or key manager nodes:

```
bwrap: No permissions to creating new namespace, likely because the kernel does
not allow non-privileged user namespaces. On e.g. debian this can be enabled
with 'sysctl kernel.unprivileged_userns_clone=1'
```

In this case do as indicated in the message and run:

```
sysctl kernel.unprivileged_userns_clone=1
```

This could also happen if you are running in a Docker container without
specifying additional options at startup. See the [Using the Development Docker
Image] section for details.

<!-- markdownlint-disable line-length -->
[sandboxing]: ../runtime/README.md#runtimes
[Using the Development Docker Image]: prerequisites.md#using-the-development-docker-image
<!-- markdownlint-enable line-length -->
