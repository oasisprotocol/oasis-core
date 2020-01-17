# Release process

The following steps should be followed when preparing a release.

## Prerequisites

Our release process relies on some tooling that needs to be available on a
maintainer's system:

- [Python] 3.5+.
- [Oasis Labs' towncrier fork].
- [Punch] 2.0.x.

Most systems should already have [Python] pre-installed.

To install [Oasis Labs' towncrier fork] and [Punch], use [pip]:

```bash
pip3 install https://github.com/oasislabs/towncrier/archive/oasis-master.tar.gz \
  punch.py~=2.0.0
```

You might want to install the packages to a [Python virtual environment] or
via so-called [User install] (i.e. isolated to the current user).

[Python]: https://www.python.org/
[Oasis Labs' towncrier fork]: https://github.com/oasislabs/towncrier
[Punch]: https://github.com/lgiordani/punch
[pip]: https://pip.pypa.io/en/stable/
[Python virtual environment]: https://packaging.python.org/tutorials/installing-packages/#creating-virtual-environments
[User install]: https://pip.pypa.io/en/stable/user_guide/#user-installs

## Tooling

Our [Make] tooling has some targets that automate parts of the release process
and try to make it less error-prone:

- `changelog`: Assembles the [Change Log] from the [Change Log fragments] using
  the [towncrier] utility.
- `tag-next-release`: After performing a bunch of sanity checks, it tags the
  git origin remote's release branch's `HEAD` with the `v<NEXT-VERSION>` tag
  and pushes it to the remote.

Note that both targets depend on the `fetch-git` target which fetches the latest
changes (including tags) from the git origin remote to ensure the computed next
version and other things are always up-to-date.

The next version of Oasis Core's regularly scheduled release is computed
automatically using the [Punch] utility and the configuration in the
`.punch_config.py` file based on the latest version tag present in git origin
remote's `master` branch.

To override the automatically computed next version, one can pass the
`NEXT_VERSION` environment variable when calling [Make].

It is also possible to set the following environment variables to customize the
release process:

- `OASIS_CORE_GIT_ORIGIN_REMOTE` (default: `origin`): Name of the git remote
  pointing to the canonical upstream git repository.
- `RELEASE_BRANCH` (default: `master`): Name of the branch where to tag the next
  release.

[Make]: https://en.wikipedia.org/wiki/Make_(software)
[Change Log]: ../CHANGELOG.md
[Change Log fragments]: ../.changelog/README.md
[towncrier]: https://github.com/hawkowl/towncrier

## Preparing a regular release

### Prepare the Change Log

Before a release, all [Change Log fragments] should be assembled into a new
section of the [Change Log] using the `changelog` [Make] target.

Create a new branch, e.g. `<GITHUB-NAME>/changelog-<NEXT-VERSION>`, and then
run [Make]:

```bash
git checkout -b <GITHUB-NAME>/changelog-<NEXT-VERSION>
make changelog
```

Review the staged changes and make appropriate adjustment to the Change Log
(e.g. re-order entries, make formatting/spelling fixes, ...).

After you are content with the changes, commit them, push them to the origin
and make a pull request.

Once the pull request had been reviewed and merged, proceed to the next step.

### Tag the next release

To create a signed git tag from the latest commit in origin remote's `master`
branch, use:

```bash
make tag-next-release
```

This command will perform a bunch of sanity checks to prevent common errors
while tagging the next release.

After those checks have passed, it will ask for confirmation before proceeding.

### Ensure a GitHub release was published

After the tag with the next release is pushed to the [canonical git repository],
the GitHub Actions [Release manager workflow] is triggered which uses the
[GoReleaser] tool to automatically build the binaries, prepare archives and
checksums, and publish a GitHub Release that accompanies the versioned git tag.

Browse to [Oasis Core's releases page] and make sure the new release is properly
published.

[canonical git repository]: https://github.com/oasislabs/oasis-core
[Release manager workflow]: ../.github/workflows/release.yml
[GoReleaser]: https://goreleaser.com/
[Oasis Core's releases page]: https://github.com/oasislabs/oasis-core/releases

## Preparing a bugfix/stable release

As mentioned in the [Versioning scheme] document, sometimes we will encounter a
situation when there is a major (security) fix that we want to back-port from an
upcoming release and release it, without also releasing all the other
(potentially breaking) changes.

To make the following steps easier, set the `BACKPORT_VERSION` environment
variable to the `YY.MINOR` release you want to back-port the changes to, e.g.
`20.1`:

```bash
BACKPORT_VERSION="20.1"
```

[Versioning scheme]: versioning.md

### Create a `stable/YY.MINOR.x` branch

Prepare a new branch from the appropriate tag and push it to the origin:

```bash
git checkout -b stable/${BACKPORT_VERSION}.x v${BACKPORT_VERSION}
git push -u origin stable/${BACKPORT_VERSION}.x
```

### Back-port the changes

Create a new branch, e.g.
`<GITHUB-NAME>/stable/${BACKPORT_VERSION}.x/backport-foo`, from the
`stable/${BACKPORT_VERSION}.x` branch:

```bash
git checkout -b <GITHUB-NAME>stable/${BACKPORT_VERSION}.x/backport-foo
    stable/${BACKPORT_VERSION}.x
```

After back-porting all the desired changes, push it to the origin and make a
pull request against the `stable/${BACKPORT_VERSION}.x` branch.

### Prepare the Change Log for the bugfix/stable release

As with a regular release, the back-ported changes should include the
corresponding [Change Log fragments] that need to be assembled into a new
section of the [Change Log] using the `changelog` [Make] target.

Create a new branch, e.g.
`<GITHUB-NAME>/stable/${BACKPORT_VERSION}.x/changelog-<NEXT-VERSION>`, from the
`stable/${BACKPORT_VERSION}.x` branch:

```bash
git checkout -b <GITHUB-NAME>/stable/${BACKPORT_VERSION}.x/changelog-<NEXT-VERSION> \
    stable/${BACKPORT_VERSION}.x
```

Then run [Make]'s `changelog` target and manually set the `NEXT_VERSION`
environment variable to the appropriate version, e.g. `${BACKPORT_VERSION}.1`,
and over-ride the release branch by setting the `RELEASE_BRANCH` environment
variable to `stable/${BACKPORT_VERSION}.x`:

```bash
NEXT_VERSION=${BACKPORT_VERSION}.1 \
RELEASE_BRANCH=stable/${BACKPORT_VERSION}.x \
make changelog
```

After reviewing the staged changes, commit them, push the changes to the origin
and make a pull request against the `stable/${BACKPORT_VERSION}.x` branch.

Once the pull request had been reviewed and merged, proceed to the next step.

### Tag the bugfix/stable release

As with a regular release, create a signed git tag from the latest commit in
origin remote's release branch.
Again, you need to manually set the `NEXT_VERSION` environment variable to the
appropriate version, e.g. `${BACKPORT_VERSION}.1`, and over-ride the release
branch by setting the `RELEASE_BRANCH` environment variable to
`stable/${BACKPORT_VERSION}.x`:

```bash
NEXT_VERSION=${BACKPORT_VERSION}.1 \
RELEASE_BRANCH=stable/${BACKPORT_VERSION}.x \
make tag-next-release
```

After the sanity checks have passed, it will ask for confirmation before
proceeding.

### Ensure a GitHub release for the bugfix/stable release was published

Similar to a regular release, after the tag with the next release is pushed to
the [canonical git repository], the GitHub Actions [Release manager workflow] is
triggered which uses the [GoReleaser] tool to automatically build a new release.

Browse to [Oasis Core's releases page] and make sure the new bugfix/stable
release is properly published.
