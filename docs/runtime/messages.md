# Runtime Messages

In order to enable runtimes to perform actions in the consensus layer on their
behalf, they can emit _messages_ in each round.

## Supported Messages

The following sections describe the methods supported by the consensus roothash
service.

### Staking Method Call

The staking method call message enables a runtime to call one of the supported
[staking service methods].

**Field name:**

```
staking
```

**Body:**

```golang
type StakingMessage struct {
    cbor.Versioned

    Transfer *staking.Transfer `json:"transfer,omitempty"`
    Withdraw *staking.Withdraw `json:"withdraw,omitempty"`
}
```

**Fields:**

- `v` must be set to `0`.
- `transfer` indicates that the [`staking.Transfer` method] should be executed.
- `withdraw` indicates that the [`staking.Withdraw` method] should be executed.

Exactly one of the supported method fields needs to be non-nil, otherwise the
message is considered malformed.

[staking service methods]: ../consensus/services/staking.md#methods
[`staking.Transfer` method]: ../consensus/services/staking.md#transfer
[`staking.Withdraw` method]: ../consensus/services/staking.md#withdraw

## Limits

The maximum number of runtime messages that can be emitted in a single round is
limited by the `executor.max_messages` option in the runtime descriptor. Its
upper bound is the [`max_messages` consensus parameter] of the roothash service.

<!-- markdownlint-disable line-length -->
[`max_messages` consensus parameter]: ../consensus/services/roothash.md#consensus-parameters
<!-- markdownlint-enable line-length -->
