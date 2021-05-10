# ADR 0009: Ed25519 Signature Verification Semantics

## Changelog

- 2021-05-10: Initial version

## Status

Informative

## Context

> In programming, it's often the buts in the specification that kill you.
>
> -- Boris Beizer

For a large host of reasons, mostly historical, there are numerous definitions
of "Ed25519 signature validation" in the wild, which have the potential to
be mutually incompatible.  This ADR serves to provide a rough high-level
overview of the issue, and to document the current definition of "Ed25519
signature verification" as used by Oasis Core.

## Decision

The Oasis Core consensus layer (and all of the Go components) currently uses
the following Ed25519 verification semantics.

- Non-canonical s is rejected (MUST enforce `s < L`)
- Small order A/R are rejected
- Non-canonical A/R are accepted
- The cofactored verification equation MUST be used (`[8][S]B = [8]R + [8][k]A`)
- A/R may have a non-zero torsion component.

### Reject Non-canonical s

Ed25519 signatures are trivially malleable unless the scalar component is
constrained to `0 <= s < L`, as is possible to create valid signatures
from an existing public key/message/signature tuple by adding L to s.

This check is mandated in all recent formulations of Ed25519 including
but not limited to RFC 8032 and FIPS 186-5, and most modern implementations
will include this check.

Note: Only asserting that `s[31] & 224 == 0` as done in older implementations
is insufficient.

### Reject Small Order A/R

Rejecting small order A is required to make the signature scheme strongly
binding (resilience to key/message substitution attacks).

Rejecting (or accepting) small order R is not believed to have a security
impact.

### Accept Non-canonical A/R

The discrete logarithm of the Ed25519 points that have a valid non-canonical
encoding and are not small order is unknown, and accepting them is not
believed to have a security impact.

Note: RFC 8032 and FIPS 186-5 require rejecting non-canonically encoded
points.

### Cofactored Verification Equation

There are two forms of the Ed25519 verification equation commonly in use,
`[S]B = R + [k]A` (cofactor-less), and `[8][S]B = [8]R + [8][k]A`
(cofactored), which are mutually incompatible in that it is possible
to produce signatures that pass with one and fail with the other.

The cofactored verification equation is explicitly required by FIPS 186-5,
and is the only equation that is compatible with batch signature verification.
Additionally, the more modern lattice-reduction based technique for fast
signature verification is incompatible with existing implementations unless
cofactored.

### Accept A/R With Non-zero Torsion

No other library enforces this, the check is extremely expensive, and
with how Oasis Core currently uses Ed25519 signatures, this has no security
impact.  In the event that Oasis Core does exotic things that, for example,
require that the public key is in the prime-order subgroup, this must be
changed.

## Consequences

### Positive

The verification semantics in use by Oasis Core provides the following
properties:

- SUF-CMA security
- Non-repudiation (strong binding)
- Compatibility with batch and lattice reduction based verification.

### Negative

The combination of "reject small order A/R" and "accept non-canonical A/R"
is difficult to test as it is not easily possible to generate valid
signatures that meet both conditions.

### Neutral

### Future Improvements

WARNING: Any changes to verification semantics are consensus breaking.

- Consider switching to the "Algorithm 2" definition, for ease of testing
  and because it is the default behavior provided by curve25519-voi.
- Consider switching to ZIP-215 semantics, to be inline with other projects,
  more library support (Give up on strong binding).
- Switching to ristretto255 (sr25519) eliminates these problems entirely.

## Recomendations For Future Projects

The definition used in Oasis Core is partly historical.  New code should
strongly consider using one of FIPS 186-5, Algorithm 2, or ZIP-215 semantics.

## References

<!-- markdownlint-disable line-length -->
- [Taming the many EdDSAs](https://eprint.iacr.org/2020/1244.pdf)
- [Explicitly Defining and Modifying Ed25519 Validation Rules](https://zips.z.cash/zip-0215)
<!-- markdownlint-enable line-length -->