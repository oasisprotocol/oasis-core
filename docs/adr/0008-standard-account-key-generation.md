# ADR 0008: Standard Account Key Generation

## Changelog

- 2021-05-07: Add test vectors and reference implementation, extend Consequences
  section
- 2021-04-19: Switch from BIP32-Ed25519 to SLIP-0010 for hierarchical key
  derivation scheme
- 2021-01-27: Initial draft

## Status

Accepted

## Context

Currently, each application interacting with the [Oasis Network] defines its own
method of generating an account's private/public key pair.

[Account]'s public key is in turn used to derive the account's address of the
form `oasis1 ... 40 characters ...` which is used to for a variety of operations
(i.e. token transfers, delegations/undelegations, ...) on the network.

The blockchain ecosystem has developed many standards for generating keys which
improve key storage and interoperability between different applications.

Adopting these standards will allow the Oasis ecosystem to:

- Make key derivation the same across different applications (i.e. wallets).
- Allow users to hold keys in hardware wallets.
- Allow users to hold keys in cold storage more reliably (i.e. using the
  familiar 24 word mnemonics).
- Define how users can generate multiple keys from a single seed (i.e.
  the 24 or 12 word mnemonic).

## Decision

### Mnemonic Codes for Master Key Derivation

We use Bitcoin's [BIP-0039]: _Mnemonic code for generating deterministic keys_
to derivate a binary seed from a mnemonic code.

The binary seed is in turn used to derive the _master key_, the root key from
which a hierarchy of deterministic keys is derived, as described in
[Hierarchical Key Derivation Scheme][hd-scheme].

We strongly recommend using 24 word mnemonics which correspond to 256 bits of
entropy.

### Hierarchical Key Derivation Scheme

We use Sathoshi Labs' [SLIP-0010]: _Universal private key derivation from master
private key_, which is a superset of
Bitcoin's [BIP-0032]: _Hierarchical Deterministic Wallets_ derivation algorithm,
extended to work on other curves.

Account keys use the [edwards25519 curve] from the Ed25519 signature scheme
specified in [RFC 8032].

### Key Derivation Paths

We adapt [BIP-0044]: _Multi-Account Hierarchy for Deterministic Wallets_ for
generating deterministic keys where `coin_type` equals 474, as assigned to the
Oasis Network by [SLIP-0044].

The following [BIP-0032] path should be used to generate keys:

```
m/44'/474'/x'
```

where `x` represents the key number.

Note that all path levels are _hardened_, e.g. `44'` is `44 | 0x8000000` or
`44 + 2^31`.

The key corresponding to key number 0 (i.e. `m/44'/474'/0'`) is called the
_primary key_.

The account corresponding to the _primary key_ is called the _primary account_.
Applications (i.e. wallets) should use this account as a user's default Oasis
account.

## Rationale

BIPs and SLIPs are industry standards used by a majority of blockchain projects
and software/hardware wallets.

### SLIP-0010 for Hierarchical Key Derivation Scheme

[SLIP-0010] defines a hierarchical key derivation scheme which is a superset of
[BIP-0032] derivation algorithm extended to work on other curves.

In particular, we use their adaptation for the [edwards25519 curve].

#### Adoption

It is used by Stellar ([SEP-0005]).

It is supported by [Ledger] and [Trezor] hardware wallets.

It is commonly used by Ledger applications, including:

- [Stellar's Ledger app][stellar-ledger-slip10],
- [Solana's Ledger app][solana-ledger-slip10],
- [NEAR Protocol's Ledger app][near-ledger-slip10],
- [Siacoin's Ledger app][sia-ledger-slip10],
- [Hedera Hashgraph's Ledger app][hedera-ledger-slip10].

#### Difficulties in Adapting BIP-0032 to edwards25519 Curve

Creating a hierarchical key derivation scheme for the [edwards25519 curve]
proved to be very challenging due to edwards25519's small cofactor and bit
"clamping".

[BIP-0032] was designed for the [secp256k1] elliptic curve with a prime-order
group. For performance reasons, edwards25519 doesn't provide a prime-order group
and provides a group of order _h_ * _l_ instead, where _h_ is a small co-factor
(8) and _l_ is a 252-bit prime.

While using a co-factor offers better performance, it has proven to be a source
of issues and vulnerabilities in higher-layer protocol implementations as
[described by Risretto authors][risretto-cofactor-issues].

Additionally, edwards25519 curve employs bit "clamping". As [described by Trevor
Perrin][trevor-perrin-clamping], low bits are "clamped" to deal with
small-subgroup attacks and high bits are "clamped" so that:

- the scalar is smaller than the subgroup order, and
- the highest bit set is constant in case the scalar is used with a
  non-constant-time scalar multiplication algorithm that leaks based on the
  highest set bit.

These issues were discussed on [modern crypto]'s mailing list [[1]][
moderncrypto-ed25519-hd1], [[2]][moderncrypto-ed25519-hd2].

[SLIP-0010] avoids these issues because it doesn't try to support non-hardened
parent public key to child public key derivation and only supports hardened
private parent key to private child key derivation when used with the
edwards25519 curve.

### Shorter Key Derivation Paths

Similar to Stellar's [SEP-0005], we decided not to use the full [BIP-0032]
derivation path specified by [BIP-0044] because [SLIP-0010]'s scheme for
[edwards25519 curve] only supports hardened private parent key to private child
key derivation and additionally, the Oasis Network is account-based rather than
[UTXO]-based.

[Trezor] follows the same scheme for account-based blockchain networks as
described in their [BIP-44 derivation paths][trezor-bip44-paths] document.

## Test Vectors

<!-- markdownlint-disable line-length -->
```json
[
  {
    "kind": "standard account key generation",
    "bip39_mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "bip39_passphrase": "",
    "bip39_seed": "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    "oasis_accounts": [
      {
        "bip32_path": "m/44'/474'/0'",
        "private_key": "fb181e94e95cc6bedd2da03e6c4aca9951053f3e9865945dbc8975a6afd217c3ad55bbb7c192b8ecfeb6ad18bbd7681c0923f472d5b0c212fbde33008005ad61",
        "public_key": "ad55bbb7c192b8ecfeb6ad18bbd7681c0923f472d5b0c212fbde33008005ad61",
        "address": "oasis1qqx0wgxjwlw3jwatuwqj6582hdm9rjs4pcnvzz66"
      },
      {
        "bip32_path": "m/44'/474'/1'",
        "private_key": "1792482bcb001f45bc8ab15436e62d60fe3eb8c86e8944bfc12da4dc67a5c89b73fd7c51a0f059ea34d8dca305e0fdb21134ca32216ca1681ae1d12b3d350e16",
        "public_key": "73fd7c51a0f059ea34d8dca305e0fdb21134ca32216ca1681ae1d12b3d350e16",
        "address": "oasis1qr4xfjmmfx7zuyvskjw9jl3nxcp6a48e8v5e27ty"
      },
      {
        "bip32_path": "m/44'/474'/2'",
        "private_key": "765be01f40c1b78dd807e03a5099220c851cfe55870ab082be2345d63ffb9aa40f85ea84b81abded443be6ab3e16434cdddebca6e12ea27560a6ed65ff1998e0",
        "public_key": "0f85ea84b81abded443be6ab3e16434cdddebca6e12ea27560a6ed65ff1998e0",
        "address": "oasis1qqtdpw7jez243dnvmzfrhvgkm8zpndssvuwm346d"
      },
      {
        "bip32_path": "m/44'/474'/3'",
        "private_key": "759b3c2af3d7129072666677b37e9e7b6d22c8bbf634816627e1704f596f60c411ebdac05bfa37b746692733f15a02be9842b29088272354012417a215666b0e",
        "public_key": "11ebdac05bfa37b746692733f15a02be9842b29088272354012417a215666b0e",
        "address": "oasis1qqs7wl20gfppe2krdy3tm4298yt9gftxpc9j27z2"
      },
      {
        "bip32_path": "m/44'/474'/4'",
        "private_key": "db77a8a8508fd77083ba63f31b0a348441d4823e6ba73b65f354a93cf789358d8753c5da6085e6dbf5969773d27b08ee05eddcb3e11d570aaadf0f42036e69b1",
        "public_key": "8753c5da6085e6dbf5969773d27b08ee05eddcb3e11d570aaadf0f42036e69b1",
        "address": "oasis1qq8neyfkydj874tvs6ksljlmtxgw3plkkgf69j4w"
      },
      {
        "bip32_path": "m/44'/474'/5'",
        "private_key": "318e1fba7d83ca3ea57b0f45377e77391479ec38bfb2236a2842fe1b7a624e8800e1a8016629f2882bca2174f29033ec2a57747cd9d3c27f49cc6e11e38ee7bc",
        "public_key": "00e1a8016629f2882bca2174f29033ec2a57747cd9d3c27f49cc6e11e38ee7bc",
        "address": "oasis1qrdjslqdum7wwehz3uaw6t6xkpth0a9n8clsu6xq"
      },
      {
        "bip32_path": "m/44'/474'/6'",
        "private_key": "63a7f716e1994f7a8ab80f8acfae4c28c21af6b2f3084756b09651f4f4ee38606b85d0a8a9747faac85233ad5e4501b2a6862a4c02a46a0b7ea699cf2bd38f98",
        "public_key": "6b85d0a8a9747faac85233ad5e4501b2a6862a4c02a46a0b7ea699cf2bd38f98",
        "address": "oasis1qzlt62g85303qcrlm7s2wx2z8mxkr5v0yg5me0z3"
      },
      {
        "bip32_path": "m/44'/474'/7'",
        "private_key": "34af69924c04d75c79bd120e03d667ff6287ab602f9285bb323667ddf9f25c974f49a7672eeadbf78f910928e3d592d17f1e14964693cfa2afd94b79f0d49f48",
        "public_key": "4f49a7672eeadbf78f910928e3d592d17f1e14964693cfa2afd94b79f0d49f48",
        "address": "oasis1qzw2gd3qq8nse6648df32zxvsryvljeyyyl3cxma"
      },
      {
        "bip32_path": "m/44'/474'/8'",
        "private_key": "aa5242e7efe8dee05c21192766a11c46531f500ff7c0cc29ed59523c5e618792c0a24bf07953520f21c1c25882d9dbf00d24d0499be443fdcf07f2da9601d3e5",
        "public_key": "c0a24bf07953520f21c1c25882d9dbf00d24d0499be443fdcf07f2da9601d3e5",
        "address": "oasis1qqzjkx9u549r87ctv7x7t0un29vww6k6hckeuvtm"
      },
      {
        "bip32_path": "m/44'/474'/9'",
        "private_key": "b661567dcb9b5290889e110b0e9814e72d347c3a3bad2bafe2969637541451e5da8c9830655103c726ff80a4ac2f05a7e0b948a1986734a4f63b3e658da76c66",
        "public_key": "da8c9830655103c726ff80a4ac2f05a7e0b948a1986734a4f63b3e658da76c66",
        "address": "oasis1qpawhwugutd48zu4rzjdcgarcucxydedgq0uljkj"
      },
      {
        "bip32_path": "m/44'/474'/2147483647'",
        "private_key": "cc05cca118f3f26f05a0ff8e2bf5e232eede9978b7736ba10c3265870229efb19e7c2b2d03265ce4ea175e3664a678182548a7fc6db04801513cff7c98c8f151",
        "public_key": "9e7c2b2d03265ce4ea175e3664a678182548a7fc6db04801513cff7c98c8f151",
        "address": "oasis1qq7895v02vh40yc2dqfxhldww7wxsky0wgfdenrv"
      }
    ]
  },
  {
    "kind": "standard account key generation",
    "bip39_mnemonic": "equip will roof matter pink blind book anxiety banner elbow sun young",
    "bip39_passphrase": "",
    "bip39_seed": "ed2f664e65b5ef0dd907ae15a2788cfc98e41970bc9fcb46f5900f6919862075e721f37212304a56505dab99b001cc8907ef093b7c5016a46b50c01cc3ec1cac",
    "oasis_accounts": [
      {
        "bip32_path": "m/44'/474'/0'",
        "private_key": "4e9ca1a4c2ed90c90da93ea181557ef9f465f444c0b7de35daeb218f9390d98545601f761af17dba50243529e629732f1c58d08ffddaa8491238540475729d85",
        "public_key": "45601f761af17dba50243529e629732f1c58d08ffddaa8491238540475729d85",
        "address": "oasis1qqjkrr643qv7yzem6g4m8rrtceh42n46usfscpcf"
      },
      {
        "bip32_path": "m/44'/474'/1'",
        "private_key": "2d0d2e75a13fd9dc423a2db8dfc1db6ebacd53f22c8a7eeb269086ec3b443eb627ed04a3c0dcec6591c001e4ea307d65cbd712cb90d85ab7703c35eee07a77dd",
        "public_key": "27ed04a3c0dcec6591c001e4ea307d65cbd712cb90d85ab7703c35eee07a77dd",
        "address": "oasis1qp42qp8d5k8pgekvzz0ld47k8ewvppjtmqg7t5kz"
      },
      {
        "bip32_path": "m/44'/474'/2'",
        "private_key": "351749392b02c6b7a5053bc678e71009b4fb07c37a67b44558064dc63b2efd9219456a3f0cf3f4cc5e6ce52def57d92bb3c5a651fa9626b246cfec07abc28724",
        "public_key": "19456a3f0cf3f4cc5e6ce52def57d92bb3c5a651fa9626b246cfec07abc28724",
        "address": "oasis1qqnwwhj4qvtap422ck7qjxf7wm89tgjhwczpu0f3"
      },
      {
        "bip32_path": "m/44'/474'/3'",
        "private_key": "ebc13ccb62142ed5b600f398270801f8f80131b225feb278d42982ce314f896292549046214fdb4729bf7a6ee4a3bbd0f463c476acc933b2c7cce084509abee4",
        "public_key": "92549046214fdb4729bf7a6ee4a3bbd0f463c476acc933b2c7cce084509abee4",
        "address": "oasis1qp36crawwyk0gnfyf0epcsngnpuwrz0mtu8qzu2f"
      },
      {
        "bip32_path": "m/44'/474'/4'",
        "private_key": "664b95ad8582831fb787afefd0febdddcf03343cc1ca5aa86057477e0f22c93b331288192d442d3a32e239515b4c019071c57ee89f91942923dd4c1535db096c",
        "public_key": "331288192d442d3a32e239515b4c019071c57ee89f91942923dd4c1535db096c",
        "address": "oasis1qz8d2zptvf44y049g9dtyqya4g0jcqxmjsf9pqa3"
      },
      {
        "bip32_path": "m/44'/474'/5'",
        "private_key": "257600bfccc21e0bc772f4d1dcfb2834805e07959ad7bd586e7deec4a320bfcecbbfef21f0833744b3504a9860b42cb0bb11e2eb042a8b83e3ceb91fe0fca096",
        "public_key": "cbbfef21f0833744b3504a9860b42cb0bb11e2eb042a8b83e3ceb91fe0fca096",
        "address": "oasis1qz0cxkl3mftumy9l4g663fmwg69vmtc675xh8exw"
      },
      {
        "bip32_path": "m/44'/474'/6'",
        "private_key": "10d224fbbac9d6e3084dff75ed1d3ae2ce52bce3345a48bf68d1552ed7d89594defb924439e0c93f3b14f25b3cb4044f9bc9055fa4a14d89f711528e6760133b",
        "public_key": "defb924439e0c93f3b14f25b3cb4044f9bc9055fa4a14d89f711528e6760133b",
        "address": "oasis1qz3pjvqnkyj42d0mllgcjd66fkavzywu4y4uhak7"
      },
      {
        "bip32_path": "m/44'/474'/7'",
        "private_key": "517bcc41be16928d32c462ee2a38981ed15b784028eb0914cfe84acf475be342102ad25ab9e1707c477e39da2184f915669791a3a7b87df8fd433f15c926ede2",
        "public_key": "102ad25ab9e1707c477e39da2184f915669791a3a7b87df8fd433f15c926ede2",
        "address": "oasis1qr8zs06qtew5gefgs4608a4dzychwkm0ayz36jqg"
      },
      {
        "bip32_path": "m/44'/474'/8'",
        "private_key": "ee7577c5cef5714ba6738635c6d9851c43428ff3f1e8db2fe7f45fb8d8be7c55a6ec8903ca9062910cc780c9b209c7767c2e57d646bbe06901d090ad81dabe8b",
        "public_key": "a6ec8903ca9062910cc780c9b209c7767c2e57d646bbe06901d090ad81dabe8b",
        "address": "oasis1qp7w82tmm6srgxqqzragdt3269334pjtlu44qpeu"
      },
      {
        "bip32_path": "m/44'/474'/9'",
        "private_key": "5257b10a5fcfd008824e2216be17be6e47b9db74018f63bb55de4d747cae6d7bba734348f3ec7af939269f62828416091c0d89e14c813ebf5e64e24d6d37e7ab",
        "public_key": "ba734348f3ec7af939269f62828416091c0d89e14c813ebf5e64e24d6d37e7ab",
        "address": "oasis1qp9t7zerat3lh2f7xzc58ahqzta5kj4u3gupgxfk"
      },
      {
        "bip32_path": "m/44'/474'/2147483647'",
        "private_key": "e7152f1b69ad6edfc05dccf67dad5305edb224669025c809d89de7e56b2cabe58c348f412819da57361cdbd7dfbe695a05dba7f24b8e7328ff991ffadab6c4d2",
        "public_key": "8c348f412819da57361cdbd7dfbe695a05dba7f24b8e7328ff991ffadab6c4d2",
        "address": "oasis1qzajez400yvnzcv8x8gtcxt4z5mkfchuh5ca05hq"
      }
    ]
  }
]
```
<!-- markdownlint-enable line-length -->

To generate these test vectors yourself, run:

```
make -C go staking/gen_account_vectors
```

We also provide more extensive test vectors. To generate them, run:

```
make -C go staking/gen_account_vectors_extended
```

## Implementation

Reference implementation is in Oasis Core's [`go/common/crypto/sakg` package].

## Alternatives

### BIP32-Ed25519 for Hierarchical Key Derivation

The [BIP32-Ed25519] (also sometimes referred to as _Ed25519 and BIP32
based on [Khovratovich]_) is a key derivation scheme that also adapts
[BIP-0032]'s hierarchical derivation scheme for the [edwards25519 curve] from
the Ed25519 signature scheme specified in [RFC 8032].

<!-- markdownlint-disable-next-line no-duplicate-heading -->
#### Adoption

It is used by Cardano ([CIP 3]) and Tezos (dubbed [bip25519 derivation scheme]).

It is supported by [Ledger] and [Trezor] hardware wallets.

It is commonly used by Ledger applications, including:

- [Polkadot's Ledger app][polkadot-ledger-normal],
- [Kusama's Ledger app][kusama-ledger-normal],
- [Zcash's Ledger app][zcash-ledger-normal],
- [Polymath's Ledger app][polymath-ledger-normal].

#### Security Concerns

Its advantage is that it supports non-hardened parent public key to child public
key derivation which enables certain use cases described in [BIP-0032][
BIP-0032-use-cases] (i.e. audits, insecure money receiver, ...).

At the same time, allowing non-hardened parent public key to child public key
derivation presents a serious security concern due to [edwards25519's co-factor
issues][diff-bip32-ed25519].

[Jeff Burdges (Web3 Foundation)] warned about a potential [key recovery attack
on the BIP32-Ed25519 scheme][BIP32-Ed25519-attack] which could occur under the
following two assumptions:

1. The Ed25519 library used in BIP-Ed25519 derivation scheme does clamping
   immediately before signing.
2. Adversary has the power to make numerous small payments in deep hierarchies
   of key derivations, observe if the victim can cash out each payment, and
   adaptively continue this process.

The first assumption is very reasonable since the [BIP32-Ed25519] paper makes
supporting this part of their specification.

<!-- markdownlint-disable no-inline-html -->
The second assumption is a bit more controversial.
The [BIP32-Ed25519] paper's specification limits the [BIP-0032] path length
(i.e. the number of levels in the tree) to 2<sup>20</sup>.
But in practice, no implementation checks that and the issue is that path length
is not an explicit part of the BIP32-Ed25519 algorithm. That means that one
doesn't know how deep in the tree the current parent/child node is. Hence, it
would be very hard to enforce the 2<sup>20</sup> path length limit.
<!-- markdownlint-enable no-inline-html -->

#### Implementation Issues

One practical issue with [BIP32-Ed25519] is that its authors didn't provide a
reference implementation and accompanying test vectors.

This has led to a number of incompatible BIP32-Ed25519 implementations.

For example, [Vincent Bernardoff's OCaml implementation][BIP32-Ed25519-OCaml]
and [Shude Li's Go implementation][BIP32-Ed25519-Go] follow [BIP32-Ed25519]'s
original master (i.e. root) key derivation specification and use SHA512 and
SHA256 for deriving the private key _k_ and chain code _c_ (respectively) from
the seed (i.e. master secret).

On the other hand, Ledger's [Python implementation in orakolo repository][
BIP32-Ed25519-orakolo] and [C implementation for their Speculos emulator][
BIP32-Ed25519-speculos] (variant with `curve` equal to `CX_CURVE_Ed25519` and
`mode` equal to `HDW_NORMAL`) use HMAC-SHA512 and HMAC-SHA256 for deriving the
private key _k_ and chain code _c_ (respectively) from the seed.

<!-- markdownlint-disable no-inline-html -->
Furthermore, [Vincent Bernardoff's OCaml implementation][
BIP32-Ed25519-OCaml-root-discard] follows [BIP32-Ed25519] paper's instructions
to discard the seed (i.e. master secret) if the master key's third highest bit
of the last byte of _k<sub>L</sub>_ is not zero.
<!-- markdownlint-enable no-inline-html -->

On the other hand, [Shude Li's Go implementation][BIP32-Ed25519-Go-root-clear]
just clears the master key's third highest bit
and [Ledger's implementations][BIP32-Ed25519-orakolo-root-repeat] repeatedly set
the seed to the master key and restart the derivation process until a master key
with the desired property is found.

Cardano uses its own variants of [BIP32-Ed25519] described in [CIP 3]. In
particular, they define different variants of master key derivation from the
seed described in [SLIP-0023].

<!-- markdownlint-disable no-inline-html -->
Lastly, some implementations, notably [Oasis' Ledger app][oasis-ledger-app],
don't use use [BIP32-Ed25519]'s private and public key directly but use the
obtained _k<sub>L</sub>_ (first 32 bytes) of the 64 byte BIP32-Ed25519 derived
private key as Ed25519's seed (i.e. non-extended private key). For more details,
see [Zondax/ledger-oasis#84].
<!-- markdownlint-enable no-inline-html -->

### Tor's Next Generation Hidden Service Keys for Hierarchical Key Derivation

The [Next-Generation Hidden Services in Tor] specification defines a
[hierarchical key derivation scheme for Tor's keys][tor-hd] which employs
multiplicative blinding instead of an additive one use by [BIP-0032].

[Jeff Burdges (Web3 Foundation)]'s post on potential [key recovery
attack on the BIP32-Ed25519 scheme][BIP32-Ed25519-attack] mentions there is
nothing wrong with this proposed scheme.
Likewise, [Justin Starry (Solana)]'s [summary of approaches to adopting BIP-0032
for Ed25519][jstarry-summary] recommends this scheme as one of the possible
approaches to adapt BIP-0032 for [edwards25519 curve].

One practical issue with using this scheme would be the absence of support by
the [Ledger] and [Trezor] hardware wallets.

## Consequences

### Positive

- Different applications interacting with the [Oasis Network] will use a
  _standards-compliant_ ([BIP-0039], [SLIP-0010], [BIP-0044]) and
  _interoperable_ account key generation process.

  Hence, there will be no vendor lock-in and users will have the option to
  easily switch between standards-compliant applications (e.g. different
  wallets).

- Using [SLIP-0010] avoids a spectrum of issues when trying to support
  non-hardened public parent key to public child key derivation with the
  [edwards25519 curve].
  Non-hardened key derivation is practically impossible to implement securely
  due to [edwards25519 curve's co-factor issues][diff-bip32-ed25519].

  This is achieved by [SLIP-0010] explicitly disallowing non-hardened public
  parent key to public child key derivation with the edwards25519 curve.

- Using a [3-level BIP-0032 path][key-derivation-paths] (i.e. `m/44'/474'/x'`)
  allows [Oasis' Ledger app][oasis-ledger-app] to implement automatic switching
  between existing (legacy) account key generation and the standard account key
  generation proposed in this ADR.

  Since the existing (legacy) account key generation used in
  [Oasis' Ledger app][oasis-ledger-app] uses a 5-level [BIP-0032] path, the
  Oasis' Ledger app will be able to automatically switch between standard and
  existing (legacy) account key generation just based on the number of levels of
  the given BIP-0032 path.

### Negative

- The account key generation proposed in this ADR is incompatible with two
  existing account key generation schemes deployed in the field:
  - [Oasis' Ledger app][oasis-ledger-app],
  - [Bitpie mobile wallet][bitpie].

  That means that these two applications will need to support two account key
  generations schemes simultaneously to allow existing users to access their
  (old) accounts generated via the existing (legacy) account key generation
  scheme.

- [SLIP-0010]'s scheme for [edwards25519 curve] only supports hardened private
  parent key to private child key derivation.

  That means it will not be possible to implement wallet features that require
  non-hardened key derivation, e.g. watch-only feature where one is able to
  monitor a hierarchical wallet's accounts just by knowing the root public key
  and deriving all accounts' public keys from that.

### Neutral

## References

- [SLIP-0010]
- Stellar's [SEP-0005]
- [Justin Starry (Solana)]'s [summary of approaches to adopting BIP-0032 for
  Ed25519][jstarry-summary]
- [Andrew Kozlik (SatoshiLabs)]'s
  [comments on BIP32-Ed25519, SLIP-0010 and SLIP-0023][kozlik-comments]

<!-- markdownlint-disable line-length -->
[hd-scheme]: #hierarchical-key-derivation-scheme
[diff-bip32-ed25519]: #difficulties-in-adapting-bip-0032-to-edwards25519-curve
[key-derivation-paths]: #key-derivation-paths
[Oasis Network]: /general/oasis-network/overview
[Account]: ../consensus/services/staking.md#accounts
[BIP-0032]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
[BIP-0032-use-cases]:
  https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#use-cases
[BIP-0039]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[BIP-0044]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
[SLIP-0010]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
[SLIP-0023]: https://github.com/satoshilabs/slips/blob/master/slip-0023.md
[SLIP-0044]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
[edwards25519 curve]: https://tools.ietf.org/html/rfc8032#section-5
[RFC 8032]: https://tools.ietf.org/html/rfc8032
[SEP-0005]:
  https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md
[Trezor]: https://trezor.io/
[Ledger]: https://www.ledger.com/
[stellar-ledger-slip10]:
  https://github.com/LedgerHQ/app-stellar/blob/fc4ec38d9abcae9bd47c95ef93feb5e1ff25961f/src/stellar.c#L42-L49
[near-ledger-slip10]:
  https://github.com/LedgerHQ/app-near/blob/40ea52a0de81d65b993a49ac705e7edad8efff0e/workdir/app-near/src/crypto/ledger_crypto.c#L24
[solana-ledger-slip10]:
  https://github.com/LedgerHQ/app-solana/blob/1c72216edf4e5358f719b164a8d1b6100988b34d/src/utils.c#L42-L51
[hedera-ledger-slip10]:
  https://github.com/LedgerHQ/app-hedera/blob/47066dcfa02379a48a65c33efb1484bb744a30a5/src/hedera.c#L21-L30
[sia-ledger-slip10]:
  https://github.com/LedgerHQ/app-sia/blob/d4dbb5a9cae2e2389d6b6a44701069e234f0f392/src/sia.c#L14
[secp256k1]: https://en.bitcoin.it/wiki/Secp256k1
[risretto-cofactor-issues]:
  https://ristretto.group/why_ristretto.html#pitfalls-of-a-cofactor
[trevor-perrin-clamping]:
  https://moderncrypto.org/mail-archive/curves/2017/000874.html
[modern crypto]: https://moderncrypto.org/
[moderncrypto-ed25519-hd1]:
  https://moderncrypto.org/mail-archive/curves/2017/000858.html
[moderncrypto-ed25519-hd2]:
  https://moderncrypto.org/mail-archive/curves/2017/000866.html
[UTXO]: https://en.wikipedia.org/wiki/Unspent_transaction_output
[Jeff Burdges (Web3 Foundation)]: https://github.com/burdges
[trezor-bip44-paths]:
  https://github.com/trezor/trezor-firmware/blob/master/docs/misc/coins-bip44-paths.md
[BIP32-Ed25519]:
  https://github.com/WebOfTrustInfo/rwot3-sf/blob/master/topics-and-advance-readings/HDKeys-Ed25519.pdf
[Khovratovich]: https://en.wikipedia.org/wiki/Dmitry_Khovratovich
[BIP32-Ed25519-attack]:
  https://web.archive.org/web/20210513183118/https://forum.w3f.community/t/key-recovery-attack-on-bip32-ed25519/44
[BIP32-Ed25519-orakolo]:
  https://github.com/LedgerHQ/orakolo/blob/0b2d5e669ec61df9a824df9fa1a363060116b490/src/python/orakolo/HDEd25519.py
[BIP32-Ed25519-orakolo-root-repeat]:
  https://github.com/LedgerHQ/orakolo/blob/0b2d5e669ec61df9a824df9fa1a363060116b490/src/python/orakolo/HDEd25519.py#L130-L133
[BIP32-Ed25519-speculos]:
  https://github.com/LedgerHQ/speculos/blob/dce04843ad7d4edbcd399391b3c39d30b37de3cd/src/bolos/os_bip32.c
[BIP32-Ed25519-OCaml]: https://github.com/vbmithr/ocaml-bip32-ed25519
[BIP32-Ed25519-OCaml-root-discard]:
  https://github.com/vbmithr/ocaml-bip32-ed25519/blob/461e6a301996d41755acd35d82cd7ab6e30a8437/src/bip32_ed25519.ml#L120-L128
[BIP32-Ed25519-Go]: https://github.com/islishude/bip32
[BIP32-Ed25519-Go-root-clear]:
  https://github.com/islishude/bip32/blob/72b7efc571fdb69a3f0ce4caf7078e5466b9273d/xprv.go#L51-L53
[Zondax/ledger-oasis#84]:
  https://github.com/Zondax/ledger-oasis/issues/84#issuecomment-827017112
[CIP 3]: https://cips.cardano.org/cips/cip3/
[bip25519 derivation scheme]:
  https://medium.com/@obsidian.systems/v2-2-0-of-tezos-ledger-apps-babylon-support-and-more-e8df0e4ea161
[polkadot-ledger-normal]:
  https://github.com/Zondax/ledger-polkadot/blob/7c3841a96caa5af6b78d49aac52b1373f10e3773/app/src/crypto.c#L44-L52
[kusama-ledger-normal]:
  https://github.com/Zondax/ledger-kusama/blob/90593207558ed82ad97123b730b07bcc33aeabf2/app/src/crypto.c#L44-L52
[zcash-ledger-normal]:
  https://github.com/Zondax/ledger-zcash/blob/61fe324e567af59d39c609b84b591e28997c1a61/app/src/crypto.c#L173-L178
[polymath-ledger-normal]:
  https://github.com/Zondax/ledger-polymesh/blob/6228950a76c945fb0b5d7fc19fa475eccdf4160d/app/src/crypto.c#L44-L52
[Next-Generation Hidden Services in Tor]:
  https://gitweb.torproject.org/torspec.git/tree/proposals/224-rend-spec-ng.txt
[tor-hd]:
  https://gitweb.torproject.org/torspec.git/tree/proposals/224-rend-spec-ng.txt#n2135
[oasis-ledger-app]: https://github.com/LedgerHQ/app-oasis
[bitpie]: /general/manage-tokens/holding-rose-tokens/bitpie-wallet
[Andrew Kozlik (SatoshiLabs)]: https://github.com/andrewkozlik
[kozlik-comments]:
  https://github.com/satoshilabs/slips/issues/703#issuecomment-515213584
[Justin Starry (Solana)]: https://github.com/jstarry
[jstarry-summary]:
  https://github.com/solana-labs/solana/issues/6301#issuecomment-551184457
[`go/common/crypto/sakg` package]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/common/crypto/sakg
<!-- markdownlint-enable line-length -->
