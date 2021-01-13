# Genesis Document

The genesis document contains a set of parameters that outline the initial state
of the [consensus layer] and its services.

For more details about the actual genesis document's API, see
[genesis API documentation].

[consensus layer]: index.md
[genesis API documentation]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/genesis/api

## Genesis Document's Hash

The genesis document's hash is computed as:

```
Base16(SHA512-256(CBOR(<genesis-document>)))
```

where:

- `Base16()` represents the hex encoding function,
- `SHA512-256()` represents the SHA-512/256 hash function as described in
  [Cryptography][crypto-hash] documentation,
- `CBOR()` represents the *canonical* CBOR encoding function as described in
  [Serialization] documentation, and
- `<genesis-document>` represents a given genesis document.

{% hint style="info" %}
This should not be confused with a SHA-1 or a SHA-256 checksum of a
[genesis file] that is used to check if the downloaded genesis file is correct.
{% endhint %}

This hash is also used for [chain domain separation][crypto-chain] as the last
part of the [domain separation] context.

[crypto-chain]: ../crypto.md#chain-domain-separation
[domain separation]: ../crypto.md#domain-separation
[crypto-hash]: ../crypto.md#hash-functions
[Serialization]: ../encoding.md
[genesis file]: #genesis-file

## Genesis File

A genesis file is a JSON document corresponding to a serialized genesis
document.

{% hint style="info" %}
For a high-level overview of the genesis file, its various sections and
parameters and the parameter values that will be used for Oasis Network Mainnet
launch, see: [Genesis File Overview].
{% endhint %}

[Genesis File Overview]:
  https://docs.oasis.dev/general/mainnet/genesis-file

### Canonical Form

The *canonical* form of a genesis file is the pretty-printed JSON file with
2-space indents, where:

- Struct fields are encoded in the order in which they are defined in the
  corresponding struct definitions.

  The genesis document is defined by the [`genesis/api.Document`] struct which
  contains pointers to other structs defining the genesis state of all
  [consensus layer] services.

- Maps have their keys converted to strings which are then encoded in
  lexicographical order.

  This is Go's default behavior. For more details, see
  [`encoding/json.Marshal()`]'s documentation.

{% hint style="info" %}
This should not be confused with the *canonical* CBOR encoding of the genesis
document that is used to derive the domain separation context as described
in the [Genesis Document's Hash] section.
{% endhint %}

This form is used to enable simple diffing/patching with the standard Unix tools
(i.e. `diff`/`patch`).

[`genesis/api.Document`]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/genesis/api#Document

[`encoding/json.Marshal()`]: https://golang.org/pkg/encoding/json/#Marshal

[Genesis Document's Hash]: #genesis-documents-hash
