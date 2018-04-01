# Contributing

TODO

## Making a release

Once everything is ready for a release, you can use the `./scripts/make-release.py` script to prepare a release. This script covers the following steps of a release process:

* Bumps all versions and versions of all internal dependencies.
* Optionally (default: no) bumps and builds Docker images.
* Commits the version bumps.
* Creates a tag for the version.
* Optionally (default: yes) calls `cargo publish` on crates.
* Optionally (default: no) bumps the repository (master) to a new pre-release version and commits this change.
* Optionally (default: yes) pushes changes to Git.

See `./scripts/make-release.py --help` for more information on usage.
