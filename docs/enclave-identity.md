# Enclave identity
In this module, an enclave persistence maintains an identity for itself.

## State
* An immutable identity for an enclave persistence. Lives as sealed data. Consists of:
  * an asymmetric key pair used to bootstrap secure communications
  * if we need monotonic counters, the IDs of those counters

Keys are generated inside the secure enclave and only leave the enclave in a sealed form (for persistence).

### Current implementation
The identity contains:

* RPC long-term contract key `E`

## Interfaces

### Enclave edge interfaces
These are not high-fidelity method signatures.
For example, outputs may be pointer arguments instead of return values.

* ECALL `identity_create() -> sealed_identity`:
  Generates an identity for a new enclave persistence and exports it in a sealed form.
  Does not start using that identity.
  Call `identity_restore` to start using it.
* ECALL `identity_restore(sealed_identity) -> public_identity`:
  Populates an enclave launch with an identity.
  The enclave launch must not have already restored an identity.
  Gives the public identity string back.
  The enclave launch caches the identity in ephemeral enclave memory so that we don't have to pass the sealed ID and unseal it for every entry.
* ECALL `identity_create_report(target_info) -> report`:
  Create a report for use in the enclave identity proof.
  The enclave launch must have an identity.
  The report data is specified below.
* ECALL `identity_set_av_report(av_report) -> void`:
  Populates an enclave launch with an attestation verification report (AVR).
  The enclave launch caches the AVR for internal use, for example, if it needs its own enclave identity proof (specified below).

### Trusted interfaces
* `IDENTITY: identity`
* `get_proof() -> identity_proof`

### Untrusted interfaces
* `EnclaveIdentity::identity_init() -> identity_proof`

## Public identity string
The public identity of an enclave persistence established this way is a string that canonically encodes the public parts of the identity.

Protocol buffers would not be ideal because [the specification does not define a canonical form](https://gist.github.com/kchristidis/39c8b310fd9da43d515c4394c3cd9510).
However, it would be sufficient to have a deterministic encoding, even if it does not define a canonical encoding.
We might be able to achieve that with a subset of Protocol buffers that excludes things like unknown fields and mappings.

### Current implementation
The public identity string is encoded as a bare Sodalite public key.

## Report data
* Quote context (64 bits)
* Version of public identity string format (64 bits, little-endian)
* Padding (128 bits)
* Digest of public identity string (256 bits)

This allows us to fit a potentially large public identity string in the report data.
It may help allow changes to the format of the public identity string.

### Current implementation
The quote context is `EkQ-Iden`.

The identity version is 0.

The padding is all zero.

The digest algorithm is SHA-512 truncated to use the first 256 bits.

## Enclave identity proof
It's the **public identity string** and an **attestation verification report** (AVR) (includes quote; quote includes report).

A compute node creates this proof by calling `create_report`, getting a revocation list, getting a quote, and verifying that quote.

To verify:
* Verify the signature (chain) on the AVR.
* Check that the AVR is recent enough.
* Check that the AVR says that the quote is okay.
* (we don't care about the quote outside of the report; that's IAS's problem)
* Check that the report data was derived from the public identity string.

This tells you *only* that all this identity came from **some** enclave persistence running **some** enclave program on **some** platform that IAS trusts (recently trusted). It's only the *authentication*. Next, for *authorization*, you would have to apply some policy to the information (e.g., the MRENCLAVE and flags in the report).

These proofs are intended to be valid for a period of time, so that the system can use keys in the enclave identity to sign and verify messages without contacting IAS. Currently we have it so that AVRs expire after a while. This would be much better if IAS would include a timestamp on its signed revocation list. Then we could allow them to be valid until the revocation list changes.
