# ADR 0002: Go Modules Compatible Git Tags

## Changelog

- 2020-09-04: Initial version

## Status

Accepted

## Context

Projects that depend on [Oasis Core's Go module], i.e.
`github.com/oasisprotocol/oasis-core/go`, need a way to depend on its particular
version.

Go Modules only allow [Semantic Versioning 2.0.0] for
[versioning of the modules][go-mod-ver] which makes it hard to work
with [Oasis Core's CalVer (calendar versioning) scheme].

The currently used scheme for Go Modules compatible Git tags is:

```
go/v0.YY.MINOR[.MICRO]
```

where:

- `YY` represents the short year (e.g. `19`, `20`, `21`, ...),
- `MINOR` represents the minor version starting with zero (e.g. `0`, `1`, `2`,
  `3`, ...),
- `MICRO` represents the final number in the version (sometimes referred to as
  the "patch" segment) (e.g. `0`, `1`, `2`, `3`, ...).

  If the `MICRO` version is `0`, it is omitted.

It turns out this only works for Oasis Core versions with the `MICRO` version
of `0` since the Go Modules compatible Git tag omits the `.MICRO` part and is
thus compatible with [Go Modules versioning requirements][go-mod-ver].

[Oasis Core's Go module]:
  https://pkg.go.dev/mod/github.com/oasisprotocol/oasis-core/go
[Semantic Versioning 2.0.0]:
  https://semver.org/spec/v2.0.0.html
[go-mod-ver]:
  https://golang.org/ref/mod#versions
[Oasis Core's CalVer (calendar versioning) scheme]: ../versioning.md

## Decision

The proposed design is to tag Oasis Core releases with the following Go Modules
compatible Git tags (in addition to the ordinary Git tags):

```
go/v0.YY0MINOR.MICRO
```

where:

- `YY` represents the short year (e.g. `19`, `20`, `21`, ...),
- `0MINOR` represents the zero-padded minor version starting with zero (e.g.
  `00`, `01`, `02`, ..., `10`, `11`, ...),
- `MICRO` represents the final number in the version (sometimes referred to as
  the "patch" segment) (e.g. `0`, `1`, `2`, `3`, ...).

Here are some examples of how the ordinary and the corresponding Go Modules
compatible Git tags would look like:

| Version       | Ordinary Git tag | Go Modules compatible Git tag  |
|:-------------:|:----------------:|:------------------------------:|
| 20.9          | `v20.9`          | `go/v0.2009.0`                 |
| 20.9.1        | `v20.9.1`        | `go/v0.2009.1`                 |
| 20.9.2        | `v20.9.2`        | `go/v0.2009.2`                 |
| 20.10         | `v20.10`         | `go/v0.2010.0`                 |
| 20.10.1       | `v20.10.1`       | `go/v0.2010.1`                 |
| 20.10.2       | `v20.10.2`       | `go/v0.2010.2`                 |
| ...           | ...              | ...                            |
| 21.0          | `v21.0`          | `go/v0.2100.0`                 |
| 21.0.1        | `v21.0.1`        | `go/v0.2100.1`                 |
| 21.0.2        | `v21.0.2`        | `go/v0.2100.2`                 |
| 21.1          | `v21.1`          | `go/v0.2101.0`                 |
| 21.1.1        | `v21.1.1`        | `go/v0.2101.1`                 |
| 21.1.2        | `v21.1.2`        | `go/v0.2101.2`                 |
| ...           | ...              | ...                            |

Using such a scheme makes the version of the Oasis Core Go module fully
compatible with the [Go Modules versioning requirements][go-mod-ver] and thus
enables users to use the familiar Go tools to check for new module versions,
i.e. `go list -m -u all`, or to obtain and require a module, i.e.
`go get github.com/oasisprotocol/oasis-core/go@latest`.

## Alternatives

An alternative scheme would be to use the following Go Modules compatible Git
tags:

```
go/v0.YY.MINOR-MICRO
```

where:

- `YY` represents the short year (e.g. `19`, `20`, `21`, ...),
- `MINOR` represents the minor version starting with zero (e.g. `0`, `1`, `2`,
  `3`, ...),
- `MICRO` represents the final number in the version (sometimes referred to as
  the "patch" segment) (e.g. `0`, `1`, `2`, `3`, ...).

Using the `-MICRO` suffix would make Go treat all such versions as a
[Go Modules pre-release version].

The consequence of that would be that all Go tools would treat such versions as
pre-releases.

For example, let's say the Oasis Core Go module would have the following Go
version tags:

- `go/v0.20.9`
- `go/v0.20.10-0`
- `go/v0.20.10-1`

and a module that depends on the Oasis Core Go module would currently require
version `v0.20.9`.

One downside would be that the `go list -m -u all` command would not notify a
user that an update, i.e. version `v0.20.10-1`, is available.

The second downside would be that using the
`go get github.com/oasisprotocol/oasis-core/go@latest` command would treat
version `v0.20.9` as the latest version and download and require this version of
the Oasis Core Go module instead of the real latest version,  `v0.20.10-1` in
this example.

[Go Modules pre-release version]:
  https://golang.org/ref/mod#glos-pre-release-version

## Consequences

### Positive

- This allow users to depend on a bugfix/patch release of the Oasis Core Go
  module in a [Go Modules versioning requirements][go-mod-ver] compatible way,
  i.e. without having to resort to pinning the requirement to a particular
  Oasis Core commit.

### Negative

- The connection between an ordinary Git tag and a Go Modules compatible Git tag
  is not very obvious.

  For example, it might not be immediately obvious that `v21.0` and
  `go/v0.2100.0` refer to the same thing.

- Using a zero-padded minor version fixed to two characters would limit the
  number of releases in a year to 100 releases.

## References

- [BadgerDB] uses a [similar scheme for tagging Go Modules compatible Git tags]
for their CalVer versioning scheme.

[BadgerDB]: https://github.com/dgraph-io/badger
[similar scheme for tagging Go Modules compatible Git tags]:
  https://github.com/dgraph-io/badger/releases
