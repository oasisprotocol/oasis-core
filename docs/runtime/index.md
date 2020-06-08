# Runtime Layer

![Runtime Layer](../images/oasis-core-runtime-details.svg)

The Oasis Core runtime layer enables independent _runtimes_ to schedule and
execute stateful computations and commit result summaries to the
[consensus layer]. In addition to [verifying and storing] the canonical runtime
state summaries the [consensus layer] also serves as the [registry] for node and
runtime metadata, a [scheduler] that elects runtime compute committees and a
coordinator for [key manager replication].

[consensus layer]: ../consensus/index.md
[verifying and storing]: ../consensus/roothash.md
[registry]: ../consensus/registry.md
[scheduler]: ../consensus/scheduler.md
[key manager replication]: ../consensus/keymanager.md

## Runtimes

A _runtime_ is effectively a replicated application with shared state. The
application can receive transactions from clients and based on those it can
perform arbitrary state mutations. This replicated state and application logic
exists completely separate from the consensus layer state and logic, but it
leverages the same consensus layer for finality with the consensus layer
providing the source of canonical state. Multiple runtimes can share the same
consensus layer.

In Oasis Core a runtime can be any executable that speaks the
[Runtime Host Protocol] which is used to communicate between a runtime and an
Oasis Core Node. The executable usually runs in a sandboxed environment with
the only external interface being the Runtime Host Protocol. The execution
environment currently includes a sandbox based on Linux namespaces and SECCOMP
optionally combined with Intel SGX enclaves for confidential computation.

![Runtime Execution](../images/oasis-core-runtime-execution.svg)

In the future this may be expanded with supporting running each runtime in its
own virtual machine and with other confidential computing technologies.

[Runtime Host Protocol]: runtime-host-protocol.md

## Operation Model

The relationship between [consensus layer services] and runtime services is best
described by a simple example of a "Runtime A" that is created and receives
transactions from clients (also see the figure above for an overview).

1. The runtime first needs to be created. In addition to developing code that
   will run in the runtime itself, we also need to specify some metadata related
   to runtime operation, including a unique [runtime identifier], and then
   [register the runtime].

1. We also need some nodes that will actually run the runtime executable and
   process any transactions from clients (compute nodes). These nodes currently
   need to have the executable available locally and must be configured as
   compute nodes.

1. In addition to compute nodes a runtime also needs storage nodes to store its
   state.

1. Both kinds of [nodes will register] on the consensus layer announcing their
   willingness to participate in the operation of Runtime A.

1. After an [epoch transition] the [committee scheduler] service will elect
   registered compute and storage nodes into different committees based on role.
   Elections are randomized based on entropy provided by the [random beacon].

1. A client may submit transactions by querying the consensus layer to get the
   current transaction scheduler committee for a given runtime, connect to it,
   send it transactions and wait for finalization by the consensus layer. In
   order to make it easier to write clients, the Oasis Node exposes a runtime
   [client RPC API] that encapsulates all this functionality in a [`SubmitTx`]
   call.

1. The transactions are batched and proceed through the transaction processing
   pipeline. At the end, results are persisted to storage and the
   [roothash service] in the consensus layer finalizes state after verifying
   that computation was performed correctly and state was correctly persisted.

1. The compute nodes are ready to accept the next batch and the process can
   repeat from step 6.

Note that the above example describes the _happy path_, a scenario where there
are no failures. Described steps mention things like verifying that computation
was performed _correctly_ and that state was _correctly stored_. How does the
consensus layer actually know that?

<!-- markdownlint-disable line-length -->
[consensus layer services]: ../consensus/index.md
[runtime identifier]: identifiers.md
[register the runtime]: ../consensus/registry.md#register-runtime
[nodes will register]: ../consensus/registry.md#register-node
[epoch transition]: ../consensus/epochtime.md
[committee scheduler]: ../consensus/scheduler.md
[random beacon]: ../consensus/beacon.md
[client RPC API]: ../oasis-node/rpc.md
[`SubmitTx`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/client/api?tab=doc#RuntimeClient.SubmitTx
[roothash service]: ../consensus/roothash.md
<!-- markdownlint-enable line-length -->

### Discrepancy Detection and Resolution

The key idea behind ensuring integrity of runtime computations is replicated
computation with discrepancy detection. This basically means that any
computation (e.g., execution of a transaction) is replicated among multiple
compute nodes. They all execute the exact same functions and produce results,
which must all match. If they don't (e.g., if even a single node produces
different results), this is treated as a discrepancy.

In case of a discrepancy, the computation must be repeated using a separate
larger compute committee which decides what the correct results were. Since all
commitments are attributable to compute nodes, any node(s) that produced
incorrect results may be subject to having their stake slashed and may be
removed from future committees.

Given the above, an additional constraint with replicated runtimes is that they
must be fully deterministic, meaning that a computation operating on the same
initial state executing the same inputs (transactions) must always produce the
same outputs and new state. In case a runtime's execution exhibits
non-determinism this will manifest itself as discrepancies since nodes will
derive different results when replicating computation.

### Compute Committee Roles and Commitments

As one of the steps above we mentioned that a compute node can be elected into
different committees based on role. A compute node may have any of the following
roles (it can have multiple roles at once):

* Transaction scheduler.
* Executor node (primary or backup).
* Merge node (primary or backup).

Subject to runtime configuration, each committee can contain multiple nodes of
the same kind (e.g., multiple executor nodes). Some are considered _primary_
which means that when some input transaction arrives they will all proceed to
execute it in a replicated fashion (e.g., they will all execute the same inputs
on the same initial state).

After execution they will sign [cryptographic commitments] specifying the
inputs, the initial state, the outputs and the resulting state. In case
computation happens inside a trusted execution environment (TEE) like Intel SGX,
the commitment will also include a platform attestation proving that the
computation took place in a given TEE.

The [roothash service] in the consensus layer will collect commitments and
verify that all nodes have indeed computed the same result. As mentioned in case
of discrepancies it will instruct nodes elected as _backups_ to repeat the
computation.

[cryptographic commitments]: ../../go/roothash/api/commitment

### Storage Receipts

All runtime persistent state is stored by storage nodes. These provide a
[Merklized Key-Value Store (MKVS)] to compute nodes. The MKVS stores immutable
state cryptographically summarized by a single root hash. When a storage node
stores a given state update, it signs a receipt stating that it is storing a
specific root. These receipts are verified by the [roothash service] before
accepting a commitment from a compute node.

[Merklized Key-Value Store (MKVS)]: ../mkvs.md
