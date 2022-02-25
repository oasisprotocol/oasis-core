# Root Hash

The roothash service is responsible for runtime commitment processing and
minimal runtime state keeping.

The service interface definition lives in [`go/roothash/api`]. It defines the
supported queries and transactions. For more information you can also check out
the [consensus service API documentation].

<!-- markdownlint-disable line-length -->
[`go/roothash/api`]: https://github.com/oasisprotocol/oasis-core/tree/master/go/roothash/api/api.go
[consensus service API documentation]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/roothash/api?tab=doc
<!-- markdownlint-enable line-length -->

## Methods

### Executor Commit

The executor commit method allows an executor node to submit commitments of an
executed computation. A new executor commit transaction can be generated using
[`NewExecutorCommitTx`].

**Method name:**

```
roothash.ExecutorCommit
```

**Body:**

```golang
type ExecutorCommit struct {
    ID      common.Namespace                `json:"id"`
    Commits []commitment.ExecutorCommitment `json:"commits"`
}
```

**Fields:**

* `id` specifies the [runtime identifier] of a runtime this commit is for.
* `commits` are the [executor commitments].

<!-- markdownlint-disable line-length -->
[`NewExecutorCommitTx`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/roothash/api?tab=doc#NewExecutorCommitTx
[runtime identifier]: ../../runtime/identifiers.md
[executor commitments]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/roothash/api/commitment?tab=doc#ExecutorCommitment
<!-- markdownlint-enable line-length -->

## Events

## Consensus Parameters

* `max_runtime_messages` (uint32) specifies the global limit on the number of
  [messages] that can be emitted in each round by the runtime. The default value
  of `0` disables the use of runtime messages.

[messages]: ../../runtime/messages.md
