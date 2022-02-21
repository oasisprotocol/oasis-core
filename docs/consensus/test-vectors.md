# Transaction Test Vectors

In order to test transaction generation, parsing and signing, we provide a set
of test vectors. They can be generated for the following consensus services:

* [Staking]
* [Registry]
* [Governance]

[Staking]: services/staking.md#test-vectors
[Registry]: services/registry.md#test-vectors
[Governance]: services/governance.md#test-vectors

## Structure

The generated test vectors file is a JSON document which provides an array of
objects (test vectors). Each test vector has the following fields:

* `kind` is a human-readable string describing what kind of a transaction the
  given test vector is describing (e.g., `"Transfer"`).

* `signature_context` is the [domain separation context] used for signing the
  transaction.

* `tx` is the human-readable _interpreted_ unsigned transaction. Its purpose is
  to make it easier for the implementer to understand what the content of the
  transaction is. **It does not contain the structure that can be serialized
  directly (e.g., [addresses] may be represented as Bech32-encoded strings while
  in the [encoded] transaction, these would be binary blobs).**

* `signed_tx` is the human-readable signed transaction to make it easier for the
  implementer to understand how the [signature envelope] looks like.

* `encoded_tx` is the CBOR-encoded (since test vectors are in JSON and CBOR
  encoding is a binary encoding it also needs to be Base64-encoded) unsigned
  transaction.

* `encoded_signed_tx` is the CBOR-encoded (since test vectors are in JSON and
  CBOR encoding is a binary encoding it also needs to be Base64-encoded) signed
  transaction. **This is what is actually broadcast to the network.**

* `valid` is a boolean flag indicating whether the given test vector represents
  a valid transaction, including:

  * transaction having a valid signature,
  * transaction being correctly serialized,
  * transaction passing basic static validation.

  _NOTE: Even if a transaction passes basic static validation, it may still
  **not** be a valid transaction on the given network due to invalid nonce, or
  due to some specific parameters set on the network._

* `signer_private_key` is the Ed25519 private key that was used to sign the
  transaction in the test vector.

* `signer_public_key` is the Ed25519 public key corresponding to
  `signer_private_key`.

[domain separation context]: ../crypto.md#domain-separation
[address]: services/staking.md#address
[encoded]: ../encoding.md
[signature envelope]: ../crypto.md#envelopes
