# Committee Scheduler

The committee scheduler service is responsible for periodically scheduling all
committees (validator, compute, key manager) based on [epoch-based time] and
entropy provided by the [random beacon].

The service interface definition lives in [`go/scheduler/api`]. It defines the
supported queries and transactions. For more information you can also check out
the [consensus service API documentation].

<!-- markdownlint-disable line-length -->
[epoch-based time]: epochtime.md
[random beacon]: beacon.md
[`go/scheduler/api`]: ../../go/scheduler/api
[consensus service API documentation]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/scheduler/api?tab=doc
<!-- markdownlint-enable line-length -->

## Events

## Validator Committee

When the committee scheduler schedules the validator committee, it additionally
assigns each member a _voting power_, which controls (i) the weight of its
votes in the consensus protocol and (ii) how often it serves as the proposer in
the consensus protocol.

The committee scheduler assigns a validator's voting power proportional to its
entity's [escrow account balance].

<!-- markdownlint-disable line-length -->
[escrow account balance]: staking.md#escrow
<!-- markdownlint-enable line-length -->
