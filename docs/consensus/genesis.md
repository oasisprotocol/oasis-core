# Genesis Document

The genesis document contains a set of parameters that outline the initial state
of the [consensus layer] and its services.

For more details about the actual genesis document's API, see
[genesis API documentation].

[consensus layer]: README.md
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

:::info

This should not be confused with a SHA-1 or a SHA-256 checksum of a
[genesis file] that is used to check if the downloaded genesis file is correct.

:::

This hash is also used for [chain domain separation][crypto-chain] as the last
part of the [domain separation] context.

[crypto-chain]: ../crypto.md#chain-domain-separation
[domain separation]: ../crypto.md#domain-separation
[crypto-hash]: ../crypto.md#hash-functions
[Serialization]: ../encoding.md
[genesis file]: #genesis-file

## Genesis File

A genesis file is a JSON file corresponding to a serialized genesis document.

:::info

For a high-level overview of the genesis file, its sections, parameters and
the parameter values that are used for the Oasis Network, see:
[Genesis File Overview].

:::

<!-- markdownlint-disable line-length -->
[Genesis File Overview]:
  https://github.com/oasisprotocol/docs/blob/main/docs/node/genesis-doc.md
<!-- markdownlint-enable line-length -->

### Canonical Form

The *canonical* form of a genesis file is the pretty-printed JSON file with
2-space indents ending with a newline, where:

- Struct fields are encoded in the order in which they are defined in the
  corresponding struct definitions.

  The genesis document is defined by the [`genesis/api.Document`] struct which
  contains pointers to other structs defining the genesis state of all
  [consensus layer] services.

- Maps have their keys converted to strings which are then encoded in
  lexicographical order.

  This is Go's default behavior. For more details, see
  [`encoding/json.Marshal()`]'s documentation.

:::info

This should not be confused with the *canonical* CBOR encoding of the genesis
document that is used to derive the domain separation context as described
in the [Genesis Document's Hash] section.

:::

This form is used to enable simple diffing/patching with the standard Unix tools
(i.e. `diff`/`patch`).

[`genesis/api.Document`]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/genesis/api#Document

[`encoding/json.Marshal()`]: https://golang.org/pkg/encoding/json/#Marshal

[Genesis Document's Hash]: #genesis-documents-hash
