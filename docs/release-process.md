# Release Process

The following steps should be followed when preparing a release.

## Prerequisites

Our release process relies on some tooling that needs to be available on a
maintainer's system:

- [Python] 3.6+.
- [Oasis' towncrier fork].
- [Punch] 2.0.x.

Most systems should already have [Python] pre-installed.

To install [Oasis' towncrier fork] and [Punch], use [pip]:

```bash
pip3 install --upgrade \
  https://github.com/oasisprotocol/towncrier/archive/oasis-master.tar.gz \
  punch.py~=2.0.0
```

You might want to install the packages to a [Python virtual environment] or
via so-called [User install] (i.e. isolated to the current user).

<!-- markdownlint-disable line-length -->
[Python]: https://www.python.org/
[Oasis' towncrier fork]: https://github.com/oasisprotocol/towncrier
[Punch]: https://github.com/lgiordani/punch
[pip]: https://pip.pypa.io/en/stable/
[Python virtual environment]:
  https://packaging.python.org/tutorials/installing-packages/#creating-virtual-environments
[User install]: https://pip.pypa.io/en/stable/user_guide/#user-installs
<!-- markdownlint-enable line-length -->

## Tooling

Our [Make] tooling has some targets that automate parts of the release process
and try to make it less error-prone:

- `changelog`: Bumps project's version with the [Punch] utility and assembles
  the [Change Log] from the [Change Log Fragments] using the
  [towncrier][Oasis' towncrier fork] utility.
- `release-tag`: After performing a bunch of sanity checks, it tags the git
  origin remote's release branch's `HEAD` with the `v<NEXT-VERSION>` tag and
  pushes it to the remote.
- `release-stable-branch`: Creates and pushes a stable branch for the current
  release.

Note that all above targets depend on the `fetch-git` target which fetches the
latest changes (including tags) from the git origin remote to ensure the
computed next version and other things are always up-to-date.

The version of the Oasis Core's next release is computed automatically using
the [Punch] utility according to the project's [Versioning] scheme.

The `changelog` Make target checks the name of the branch on which the release
is being made to know which part of the project's version to bump.

To customize the release process, one can set the following environment
variables:

- `GIT_ORIGIN_REMOTE` (default: `origin`): Name of the git remote pointing to
  the canonical upstream git repository.
- `RELEASE_BRANCH` (default: `master`): Name of the branch where to tag the next
  release.

<!-- markdownlint-disable line-length -->
[Make]:
  https://en.wikipedia.org/wiki/Make_\(software\)
[Change Log]:
  https://github.com/oasisprotocol/oasis-core/tree/master/CHANGELOG.md
[Change Log Fragments]:
  https://github.com/oasisprotocol/oasis-core/tree/master/.changelog/README.md
[Versioning]: versioning.md
<!-- markdownlint-enable line-length -->

## Preparing a Regular Release

### Bump Protocol Versions

Before a release, make sure that the proper protocol versions were bumped
correctly (see [`go/common/version/version.go`]). If not, make a pull request
that bumps the respective version(s) before proceeding with the release process.

<!-- markdownlint-disable line-length -->
[`go/common/version/version.go`]:
  https://github.com/oasisprotocol/oasis-core/tree/master/go/common/version/version.go
<!-- markdownlint-enable line-length -->

### Prepare the Change Log

Before a release, all [Change Log fragments] should be assembled into a new
section of the [Change Log] using the `changelog` [Make] target.

Create a new branch, e.g. `changelog`, and then run [Make]:

```bash
git checkout -b changelog
make changelog
```

Review the staged changes and make appropriate adjustment to the Change Log
(e.g. re-order entries, make formatting/spelling fixes, ...).

Replace the `<VERSION>` strings in the protocol versions table just below the
next version's heading with appropriate protocol versions as defined in
[go/common/version/version.go][version-file] file.

For example:

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 4.0.0     |
| Runtime Host      | 2.0.0     |
| Runtime Committee | 2.0.0     |

After you are content with the changes, commit them, push them to the origin
and make a pull request.

Once the pull request had been reviewed and merged, proceed to the next step.

<!-- markdownlint-disable line-length -->
[version-file]:
  https://github.com/oasisprotocol/oasis-core/tree/master/go/common/version/version.go
<!-- markdownlint-enable line-length -->

### Tag Next Release

To create a signed git tag from the latest commit in origin remote's `master`
branch, use:

```bash
make release-tag
```

This command will perform a bunch of sanity checks to prevent common errors
while tagging the next release.

After those checks have passed, it will ask for confirmation before proceeding.

### Ensure GitHub Release Was Published

After the tag with the next release is pushed to the [canonical git repository],
the GitHub Actions [Release manager workflow] is triggered which uses the
[GoReleaser] tool to automatically build the binaries, prepare archives and
checksums, and publish a GitHub Release that accompanies the versioned git tag.

Browse to [Oasis Core's releases page] and make sure the new release is properly
published.

### Create `stable/YY.MINOR.x` Branch

To prepare a new stable branch from the new release tag and push it to the
origin remote, use:

```bash
make release-stable-branch
```

This command will perform sanity checks to prevent common errors.

After those checks have passed, it will ask for confirmation before proceeding.

<!-- markdownlint-disable line-length -->
[canonical git repository]:
  https://github.com/oasisprotocol/oasis-core
[Release manager workflow]:
  https://github.com/oasisprotocol/oasis-core/tree/master/.github/workflows/release.yml
[GoReleaser]: https://goreleaser.com/
[Oasis Core's releases page]:
  https://github.com/oasisprotocol/oasis-core/releases
<!-- markdownlint-enable line-length -->

## Preparing a Bugfix/Stable Release

As mentioned in the [Versioning] documentation, sometimes we will want to
back-port some fixes (e.g. a security fix) and (backwards compatible) changes
from an upcoming release and release them without also releasing all the other
(potentially breaking) changes.

Set the `RELEASE_BRANCH` environment variable to the name of the stable branch
of the `YY.MINOR` release you want to back-port the changes to, e.g.
`stable/21.2.x`, and export it:

```bash
export RELEASE_BRANCH="stable/21.2.x"
```

### Back-port Changes

Create a new branch, e.g. `backport-foo-${RELEASE_BRANCH#stable/}`, from the
`${RELEASE_BRANCH}` branch:

```bash
git checkout -b backport-foo-${RELEASE_BRANCH#stable/} ${RELEASE_BRANCH}
```

After back-porting all the desired changes, push it to the origin and make a
pull request against the `${RELEASE_BRANCH}` branch.

### Prepare Change Log for Bugfix/Stable Release

As with a regular release, the back-ported changes should include the
corresponding [Change Log Fragments] that need to be assembled into a new
section of the [Change Log] using the `changelog` [Make] target.

Create a new branch, e.g. `changelog-${RELEASE_BRANCH#stable/}`, from the
`${RELEASE_BRANCH}` branch:

```bash
git checkout -b changelog-${RELEASE_BRANCH#stable/} ${RELEASE_BRANCH}
```

Then run [Make]'s `changelog` target:

```bash
make changelog
```

*NOTE: The `changelog` Make target will bump the `MICRO` part of the version
automatically.*

Replace the `<VERSION>` strings in the protocol versions table just below the
next version's heading with appropriate protocol versions as defined in
[go/common/version/version.go][version-file] file.

After reviewing the staged changes, commit them, push the changes to the origin
and make a pull request against the `${RELEASE_BRANCH}` branch.

Once the pull request had been reviewed and merged, proceed to the next step.

### Tag Bugfix/Stable Release

As with a regular release, create a signed git tag from the latest commit in
origin remote's release branch by running the `release-tag` Make target:

```bash
make release-tag
```

After the sanity checks have passed, it will ask for confirmation before
proceeding.

### Ensure GitHub Release for Bugfix/Stable Release Was Published

Similar to a regular release, after the tag with the next release is pushed to
the [canonical git repository], the GitHub Actions [Release manager workflow] is
triggered which uses the [GoReleaser] tool to automatically build a new release.

Browse to [Oasis Core's releases page] and make sure the new bugfix/stable
release is properly published.
