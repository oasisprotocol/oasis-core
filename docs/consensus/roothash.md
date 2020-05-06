# Root Hash

The roothash service is responsible for runtime commitment processing and
minimal runtime state keeping.

The service interface definition lives in [`go/roothash/api`]. It defines the
supported queries and transactions. For more information you can also check out
the [consensus service API documentation].

<!-- markdownlint-disable line-length -->
[`go/roothash/api`]: ../../go/roothash/api
[consensus service API documentation]: https://pkg.go.dev/github.com/oasislabs/oasis-core/go/roothash/api?tab=doc
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
[`NewExecutorCommitTx`]: https://pkg.go.dev/github.com/oasislabs/oasis-core/go/roothash/api?tab=doc#NewExecutorCommitTx
[runtime identifier]: ../runtime/identifiers.md
[executor commitments]: https://pkg.go.dev/github.com/oasislabs/oasis-core/go/roothash/api/commitment?tab=doc#ExecutorCommitment
<!-- markdownlint-enable line-length -->

### Merge Commit

The merge commit method allows a merge node to submit commitments of an executed
state merge. A new merge commit transaction can be generated using
[`NewMergeCommitTx`].

**Method name:**

```
roothash.MergeCommit
```

**Body:**

```golang
type ExecutorCommit struct {
    ID      common.Namespace             `json:"id"`
    Commits []commitment.MergeCommitment `json:"commits"`
}
```

**Fields:**

* `id` specifies the [runtime identifier] of a runtime this commit is for.
* `commits` are the [merge commitments].

<!-- markdownlint-disable line-length -->
[`NewMergeCommitTx`]: https://pkg.go.dev/github.com/oasislabs/oasis-core/go/roothash/api?tab=doc#NewMergeCommitTx
[merge commitments]: https://pkg.go.dev/github.com/oasislabs/oasis-core/go/roothash/api/commitment?tab=doc#MergeCommitment
<!-- markdownlint-enable line-length -->

## Events
