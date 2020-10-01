# Versioning

## Oasis Core

Oasis Core (as a whole) uses a [CalVer] (calendar versioning) scheme with the
following format:

```text
YY.MINOR[.MICRO][-MODIFIER]
```

where:

- `YY` represents short year (e.g. `19`, `20`, `21`, ...),
- `MINOR` represents the minor version starting with zero (e.g. `0`, `1`, `2`,
  `3`, ...),
- `MICRO` represents (optional) final number in the version (sometimes referred
  to as the "patch" segment) (e.g. `0`, `1`, `2`, `3`, ...).

  If the `MICRO` version is `0`, it will be omitted.

- `MODIFIER` represents (optional) build metadata, e.g. `git8c01382`.

The `YY` version must be bumped after each new calendar year.

When a regularly scheduled release is made, the `MINOR` version should be
bumped.

If there is a major fix that we want to back-port from an upcoming next release
and release it, then the `MICRO` version should be bumped.

The `MODIFIER` should be used to denote a build from an untagged (and
potentially unclean) git source. It should be of the form:

```text
gitCOMMIT_SHA[+dirty]
```

where:

- `COMMIT_SHA` represents the current commit’s abbreviated SHA.

The `+dirty` part is optional and is only present if there are uncommitted
changes in the working directory.

## Protocols (Consensus, Runtime Host, Runtime Committee)

Oasis Core’s protocol versions use [SemVer] (semantic versioning) 2.0.0 with the
following format:

```text
MAJOR.MINOR.PATCH
```

where:

- `MAJOR` represents the major version,
- `MINOR` represents the minor version,
- `PATCH` represents the patch version.

Whenever a backward-incompatible change is made to a protocol, the `MAJOR`
version must be bumped.

If a new release adds a protocol functionality in a backwards compatible manner,
the `MINOR` version must be bumped.

When only backwards compatible bug fixes are made to a protocol, the `PATCH`
version should be bumped.

### Version 1.0.0

With the release of [Oasis Core 20.10], we bumped the protocol versions to
version 1.0.0 which [signified that they are ready for production use](
https://semver.org/#how-do-i-know-when-to-release-100).

[CalVer]: http://calver.org
[SemVer]: https://semver.org/
[Oasis Core 20.10]:
  https://github.com/oasisprotocol/oasis-core/blob/v20.10/CHANGELOG.md
