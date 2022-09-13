# Oasis Core

[![Build status][buildkite-badge]][buildkite-link]
[![CI lint status][github-ci-lint-badge]][github-ci-lint-link]
[![CI reproducibility status][github-ci-repr-badge]][github-ci-repr-link]
[![Docker status][github-docker-badge]][github-docker-link]
[![Release status][github-release-badge]][github-release-link]
[![GoDev][godev-badge]][godev-link]
[![Docusaurus][docusaurus-badge]][docs-link]

<!-- NOTE: Markdown doesn't support tables without headers, so we need to
work around that and make the second (non-header) row also bold. -->
| Go            | [![Go coverage][codecov-badge]][codecov-link]       |
|:-------------:|:---------------------------------------------------:|
| **Rust**      | [![Rust coverage][coveralls-badge]][coveralls-link] |

<!-- markdownlint-disable line-length -->
[buildkite-badge]: https://badge.buildkite.com/16896a68bd8fba45d7b41fd608f26f87c726da10f7f24694a0.svg?branch=master
[buildkite-link]: https://buildkite.com/oasisprotocol/oasis-core-ci
[github-ci-lint-badge]: https://github.com/oasisprotocol/oasis-core/workflows/ci-lint/badge.svg
[github-ci-lint-link]: https://github.com/oasisprotocol/oasis-core/actions?query=workflow:ci-lint+branch:master
[github-ci-repr-badge]: https://github.com/oasisprotocol/oasis-core/workflows/ci-reproducibility/badge.svg
[github-ci-repr-link]: https://github.com/oasisprotocol/oasis-core/actions?query=workflow:ci-reproducibility
[github-docker-badge]: https://github.com/oasisprotocol/oasis-core/workflows/docker/badge.svg
[github-docker-link]: https://github.com/oasisprotocol/oasis-core/actions?query=workflow:docker
[github-release-badge]: https://github.com/oasisprotocol/oasis-core/workflows/release/badge.svg
[github-release-link]: https://github.com/oasisprotocol/oasis-core/actions?query=workflow:release
[codecov-badge]: https://codecov.io/gh/oasisprotocol/oasis-core/branch/master/graph/badge.svg
[codecov-link]: https://codecov.io/gh/oasisprotocol/oasis-core
[coveralls-badge]: https://coveralls.io/repos/github/oasisprotocol/oasis-core/badge.svg
[coveralls-link]: https://coveralls.io/github/oasisprotocol/oasis-core
[godev-badge]: https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white
[godev-link]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go?tab=subdirectories
[docusaurus-badge]: https://img.shields.io/badge/docusaurus-docs-007d9c?logo=read-the-docs&logoColor=white
[docs-link]: https://docs.oasis.io/core
<!-- markdownlint-enable line-length -->

## Note

* **Oasis Core is in active development so all APIs, protocols and data
  structures are subject to change.**
* **The code has not yet been fully audited. For security issues and other
  security-related topics, see [Security](#security).**

## Contributing

See our [Contributing Guidelines](CONTRIBUTING.md).

## Security

Read our [Security](docs/SECURITY.md) document.

## Developer Documentation

See our [developer documentation index].

[developer documentation index]: docs/README.md

## Developing and Building the System

See [a list of prerequisites] followed by [build instructions] and an example
of [setting up a local test network with a simple runtime].

<!-- markdownlint-disable line-length -->
[a list of prerequisites]: docs/development-setup/prerequisites.md
[build instructions]: docs/development-setup/building.md
[setting up a local test network with a simple runtime]: docs/development-setup/oasis-net-runner.md
<!-- markdownlint-enable line-length -->

## Directories

* `client`: Client library for talking with the runtimes.
* `docker`: Docker environment definitions.
* `go`: Oasis node.
* `keymanager-api-common`: Common keymanager code shared between client and lib.
* `keymanager-client`: Client crate for the key manager.
* `keymanager-lib`: Keymanager library crate.
* `runtime`: The runtime library that simplifies writing SGX and non-SGX
  runtimes.
* `runtime-loader`: The SGX and non-SGX runtime loader process.
* `scripts`: Bash scripts for development.
* `tests`: Runtimes, clients and resources used for E2E tests.
* `tools`: Build tools.
