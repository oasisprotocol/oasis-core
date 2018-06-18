# Contributing

Thank you for your interest in contributing to Oasis! There are many ways to contribute, and this document should not be considered encompassing.
If you have questions, please file an issue in this repository.

## Feature Requests

To request new functionality, there are two primary approaches that will be most effective at receiving input and making progress.

If the feature is `small` - a change to a single piece of functionality, or an addition that can be expressed clearly and succinctly in a few sentences, then the most appropriate place to propose it is as an issue in this repository. Such issues will typically receive `p:3` priority in their initial triage.

If the feature is more complicated, and involves protocol changes, or has potential safety or performance implications, then an RFC document is more appropriate.
These documents live in the [RFCs](https://github.com/oasislabs/rfcs) repository, new features are proposed via a Pull Request in that repository to allow for
commenting and consensus to be reached before implementation.

## Bug Reports

Bugs are a reality for any software project. We can't fix what we don't know about!

If you believe a bug report presents a security risk, please report it directly to the team, rather than as a public issue.

If you can, search issues in the repository to contribute to existing reports. We don't mind if an issue is filed, but may close it as duplicate if there's already an issue for it.

More information about what we consider to be useful bug reports is included as prompts in our default [issue template](https://github.com/oasislabs/ekiden/issues/new?template=bug_report.md).

## Building

Our development environment is documented in our main repository [README](https://github.com/oasislabs/ekiden/blob/master/README.md) documents.

## Pull Requests

Pull requests are how we accept new code. Pull requests should be made against the `master` branch.

Pull requests will have an automatic set of CI tests run against them to validate that tests pass and code meets our style guidelines.

For extra credit, squish the commits in your PR after review and before merging to provide a more intelligable history for others. Likewise, add a line or two to `CHANGELOG.md` documenting the change.

## Documentation

Documentation is always welcome! Documentation comes in several forms:
* Code-level documentation, following language specifications.
* Mechanism documentation, which live in `docs/` describe commonly used systems, like adding a new protcol definiton, or benchmarking the system.
* Protocol documentation, living in the `RFCs` repository, describe protocols and architectural design.

## Releasing

Once everything is ready for a release, you can use the `./scripts/make-release.py` script to prepare a release. This script covers the following steps of a release process:

* Bumps all versions and versions of all internal dependencies.
* Optionally (default: no) bumps and builds Docker images.
* Commits the version bumps.
* Creates a tag for the version.
* Optionally (default: yes) calls `cargo publish` on crates.
* Optionally (default: no) bumps the repository (master) to a new pre-release version and commits this change.
* Optionally (default: yes) pushes changes to Git.

See `./scripts/make-release.py --help` for more information on usage.

In addition, update `CHANGELOG.md` to archive changes in this release and begin a new section for subsequent changes.