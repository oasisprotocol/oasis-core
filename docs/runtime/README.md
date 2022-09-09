# Runtime Layer

![Runtime Layer](../images/oasis-core-runtime-details.svg)

The Oasis Core runtime layer enables independent _runtimes_ to schedule and
execute stateful computations and commit result summaries to the
[consensus layer]. In addition to [verifying and storing] the canonical runtime
state summaries the [consensus layer] also serves as the [registry] for node and
runtime metadata, a [scheduler] that elects runtime compute committees and a
coordinator for [key manager replication].

[consensus layer]: ../consensus/README.md
[verifying and storing]: ../consensus/services/roothash.md
[registry]: ../consensus/services/registry.md
[scheduler]: ../consensus/services/scheduler.md
[key manager replication]: ../consensus/services/keymanager.md

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
   current executor committee for a given runtime, connect to it, publish
   transactions and wait for finalization by the consensus layer. In order to
   make it easier to write clients, the Oasis Node exposes a runtime
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
[consensus layer services]: ../consensus/README.md
[runtime identifier]: identifiers.md
[register the runtime]: ../consensus/services/registry.md#register-runtime
[nodes will register]: ../consensus/services/registry.md#register-node
[epoch transition]: ../consensus/services/epochtime.md
[committee scheduler]: ../consensus/services/scheduler.md
[random beacon]: ../consensus/services/beacon.md
[client RPC API]: ../oasis-node/rpc.md
[`SubmitTx`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/client/api?tab=doc#RuntimeClient.SubmitTx
[roothash service]: ../consensus/services/roothash.md
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

A compute node can be elected into an executor committee and may have one of the
following roles:

* Primary executor node. At any given round a single node is selected among all
the primary executor nodes to be a _transaction scheduler node_ (roughly equal
to the role of a _block proposer_).
* Backup executor node. Backup nodes can be activated by the consensus layer in
case it determines that there is a discrepancy.

The size of the primary and backup executor committees, together with other
related parameters, can be configured on a per-runtime basis. The _primary_
nodes are the ones that will batch incoming transactions into blocks and execute
the state transitions to derive the new state root. They perform this in a
replicated fashion where all the primary executor nodes execute the same inputs
(transactions) on the same initial state.

After execution they will sign [cryptographic commitments] specifying the
inputs, the initial state, the outputs and the resulting state. In case
computation happens inside a trusted execution environment (TEE) like Intel SGX,
the commitment will also include a platform attestation proving that the
computation took place in a given TEE.

The [roothash service] in the consensus layer will collect commitments and
verify that all nodes have indeed computed the same result. As mentioned in case
of discrepancies it will instruct nodes elected as _backups_ to repeat the
computation.

<!-- markdownlint-disable line-length -->
[cryptographic commitments]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/roothash/api/commitment?tab=doc
<!-- markdownlint-enable line-length -->

### Storage Receipts

All runtime persistent state is stored by storage nodes. These provide a
[Merklized Key-Value Store (MKVS)] to compute nodes. The MKVS stores immutable
state cryptographically summarized by a single root hash. When a storage node
stores a given state update, it signs a receipt stating that it is storing a
specific root. These receipts are verified by the [roothash service] before
accepting a commitment from a compute node.

[Merklized Key-Value Store (MKVS)]: ../mkvs.md

### Suspending Runtimes

Since periodic maintenance work must be performed on each epoch transition
(e.g., electing runtime committees), fees for that maintenance are paid by any
nodes that register to perform work for a specific runtime. Fees are pre-paid
for the number of epochs a node registers for. If there are no committees for a
runtime on epoch transition, the runtime is suspended for the epoch.
The runtime is also suspended in case the registering entity no longer has
enough stake to cover the entity and runtime deposits. The runtime will be
resumed on the epoch transition if runtime nodes will register and the
registering entity will have enough stake.

### Emitting Messages

Runtimes may [emit messages] to instruct the consensus layer what to do on their
behalf. This makes it possible for runtimes to [own staking accounts].

[emit messages]: messages.md
[own staking accounts]: ../consensus/services/staking.md#runtime-accounts
