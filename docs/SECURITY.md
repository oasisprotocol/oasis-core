# Security

At [Oasis Foundation], we take security very seriously and we deeply appreciate
any effort to discover and fix vulnerabilities in [Oasis Core] and other
projects powering the [Oasis Network].

We prefer that security reports be sent through our [private bug bounty program
linked on our website](https://oasisprotocol.org/security).

We sketch out the general classification of the kinds of errors
below. This is not intended to be an exhaustive list.

<!-- markdownlint-disable line-length -->
[Oasis Foundation]: https://oasisprotocol.org/
[Oasis Core]: https://github.com/oasisprotocol/oasis-core
[Oasis Network]: https://github.com/oasisprotocol/docs/blob/main/docs/general/oasis-network/README.md
<!-- markdownlint-enable line-length -->

## Specifications

Our [papers] specify what we are building.  Additional designs and
specifications may be made available later.

NB: Our designs/specifications describe what we are building toward,
and do not necessarily reflect the state of the current iteration of
the system.  Implementation/specification mismatches in such cases are
expected.

- Conceptual errors.

- Ambiguities, inconsistencies, or incorrect statements.

- Mismatch between specifications and implementation of any subsystems
  / modules, when the implementation is considered complete.

[papers]: https://oasisprotocol.org/papers

## Contract Computational/Data Integrity

- Race conditions / non-determinism.  These may introduce a denial of
  service opportunity, or a way to force the system into slow path /
  recovery mode.

- Conditions under which compute nodes may cause a bogus transaction
  result to be accepted (committed to the blockchain) by the system.

### Tendermint

- Tendermint has its own vulnerability disclosure policy and bug
  bounty, so in general issues in the core tendermint code should be
  reported
  [there](https://github.com/tendermint/tendermint/blob/master/SECURITY.md).

- Oasis Labs code that misuses Tendermint code, i.e., in violation of
  API/contract, would definitely be in scope.

### Discrepancy Detection

- Situations where a discrepant computation is not detected.

- Situations where a discrepancy occurs but no receipts are
  generated/retained for blame assignment / slashing after slow-path
  recovery.

### Storage

- We use immutable authenticated data structures.

  - Undetected mutations.  E.g., situations where a conceptually
    immutable data structure can be changed without updating hashes
    (and thus getting a new ID).

  - Missing/incomplete ADS proof generation or verification.

- Availability failures.  Potential DoS, e.g., malformed requests that
  cause node panics, etc.

## Contract Confidentiality

- Cryptography: information leak or integrity failure, e.g., due to a
  poor choice of signature algorithm, AEAD schemes, etc, or to
  improper usage of the cryptographic schemes.  NB: side channels are
  out of scope.

- TEE misuse, model failures.

## Availability

Bugs that create a potential for DOS or DDOS attack, e.g.:

- Amplification attacks.

- Failstop crashes / panics.

- Deadlocks / livelocks.
