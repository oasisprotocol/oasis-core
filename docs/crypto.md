# Cryptography

## Hash Functions

In most places where cryptographic hashes are required, we use the SHA-512/256
hash function as specified in [FIPS 180-4].

[FIPS 180-4]: https://csrc.nist.gov/publications/detail/fips/180/4/final

## Signatures

All cryptographic signatures are made using the Ed25519 (pure) scheme specified
in [RFC 8032].

[RFC 8032]: https://tools.ietf.org/html/rfc8032

### Domain Separation

When signing messages and verifying signatures we require the use of a domain
separation context in order to make sure the messages cannot be repurposed in
a different protocol.

The domain separation scheme adds a preprocessing step to any signing and
verification operation. The step computes the value that is then signed/verified
using Ed25519 as usual.

The message to be signed is computed as follows:

```
M := H(Context || Message)
```

Where:

* `H` is the SHA-512/256 cryptographic hash function.
* `Context` is the domain separation context string.
* `Message` is the original message.

The Ed25519 signature is then computed over `M`.

*NOTE: While using something like Ed25519ph/ctx as specified by [RFC 8032] would
be ideal, unfortunately these schemes are not supported in many hardware
security modules which is why we are using an ad-hoc scheme.*

#### Contexts

All of the domain separation contexts used in Oasis Core use the following
convention:

* They start with the string `oasis-core/`,
* followed by the general module name,
* followed by the string `: `,
* followed by a use case description.

The maximum length of a domain separation context is 255 bytes to be compatible
with the length defined in [RFC 8032].

The Go implementation maintains a registry of all used contexts to make sure
they are not reused incorrectly.

#### Chain Domain Separation

For some signatures, we must ensure that the domain separation context is tied
to the given network instance as defined by the genesis document. This ensures
that such messages cannot be replayed on a different network.

For all domain separation contexts where chain domain separation is required,
we use the following additional convention:

* The context is as specified by the convention in the section above,
* followed by the string ` for chain `,
* followed by the [genesis document's hash].

[genesis document's hash]: consensus/genesis.md#genesis-documents-hash

### Envelopes

There are currently two kinds of envelopes that are used when signing CBOR
messages:

* [Single signature envelope (`Signed`)] contains the CBOR-serialized blob in
  the `untrusted_raw_value` field and a single `signature`.

* [Multiple signature envelope (`MultiSigned`)] contains the CBOR-serialized
  blob in the `untrusted_raw_value` field and multiple signatures in the
  `signatures` field.

The envelopes are themselves CBOR-encoded. While no separate test vectors are
provided, [those used for transactions] can be used as a reference.

## Standard Account Key Generation

When generating an [account]'s private/public key pair, follow [ADR 0008:
Standard Account Key Generation][ADR 0008].

<!-- markdownlint-disable line-length -->
[Single signature envelope (`Signed`)]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/common/crypto/signature?tab=doc#Signed
[Multiple signature envelope (`MultiSigned`)]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/common/crypto/signature?tab=doc#MultiSigned
[those used for transactions]: consensus/test-vectors.md
[account]: consensus/services/staking.md#accounts
[ADR 0008]:
  https://github.com/oasisprotocol/adrs/blob/master/0008-standard-account-key-generation.md
<!-- markdownlint-enable line-length -->
