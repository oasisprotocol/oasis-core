# Change Log fragments

This directory collects Change Log fragments:
short files that each contain a snippet of Markdown formatted text that will
be assembled using [towncrier] to form the [Change Log] section for the next
release.

## Description

A Change Log fragment should be a description of aspects of the change (if
any) that are relevant to users.

_NOTE: This could be very different from the commit message and pull request
description, which are a description of the change as relevant to the people
working on the code itself._

The description should follow the familiar [style of Git commit messages],
i.e. a separate subject line giving the change's summary, followed by a more
detailed explanation in the body.

In case of simpler descriptions, one can omit the description's body.

_NOTE: Lines should be wrapped at 78 characters because Change Log fragments
will be listed as bullets indented by 2 spaces so they should be 2 characters
shorter than ordinary lines._

An example:

```text
Remove staking-related roothash messages

There is no longer a plan to support direct manipulation of the staking
accounts from the runtimes in order to isolate the runtimes from corrupting
the consensus layer.

To reduce complexity, the staking-related roothash messages were removed.
The general roothash message mechanism stayed as-is since it may be useful in
the future, but any commits with non-empty messages are rejected for now.
```

_NOTE: The [towncrier] tool will automatically augment each subject line with
a link to an appropriate issue/pull request._

## File name

Each Change Log fragment should be in its own file named according to the
following syntax:

```text
<ISSUE>.<TYPE>[.<COUNTER>].md
```

where:

- `<ISSUE>` is a GitHub issue or pull request number.

  If your pull request closes an issue, use that number here.

  If there is no issue for the change you've implemented, then after you
  submit the pull request and get your pull request number, amend your
  commit(s) with an appropriately named Change Log fragment.

- `<TYPE>` is one of:

  - `process`: a change in Oasis Core's processes (e.g. development process,
    release process, ...),
  - `breaking`: a removal of functionality or a breaking change,
  - `cfg`: a (possibly breaking) configuration change,
  - `feature`: a new feature,
  - `bugfix`: a bug fix,
  - `doc`: a documentation-related change,
  - `internal`: an internal change of interest to developers and maintainers,
  - `trivial`: a trivial change that is _not_ included in the Change Log.

- `.<COUNTER>` part is optional and can be used when a single issue or pull
  request needs multiple Change Log fragments. For example, when a pull
  request contains multiple bug fixes and each bug fix deserves a separate
  Change Log fragment describing what it fixes.

Example file names:

- `1234.feature.md`,
- `2345.bugfix.md`,
- `3456.bugfix.1.md`,
- `3456.bugfix.2.md`.

## Multiple issues / pull requests for a single fragment

Sometimes referencing multiple issues or pull requests in a Change Log
fragment is desired.

For example:

- when a single Change Log fragment describes a change that resolves multiple
  issues, or
- when a sub-sequent issue / pull request augments a change that already has a
  corresponding Change Log fragment.

In this case, you need to augment (if necessary) the original Change Log
fragment (e.g. `1234.feature.md`) and copy it to a new file which has the new
issue or pull request number in its name (e.g. `1356.feature.md`).
The [towncrier] tool will automatically detect a duplicate Change Log fragment
and combine issue / pull request numbers in a single Change Log entry.

_NOTE: You can repeat this process to refer to as many issues / pull requests
as needed._

## Render Change Log preview

To get a preview of how your change (and other changes queued up in this
directory) will look in the Change Log, install [Oasis Labs' towncrier fork]
with:

```bash
pip3 install --upgrade \
  https://github.com/oasislabs/towncrier/archive/oasis-master.tar.gz
```

_NOTE: [towncrier] requires Python 3.5+._

And then run:

```bash
towncrier build --version <NEXT-VERSION> --draft
```

replacing `<NEXT-VERSION>` with the next version of Oasis Core that this
Change Log section is for.

_NOTE: You can use any version for the preview, it doesn't really matter._

[Change Log]: ../CHANGELOG.md
[towncrier]: https://github.com/hawkowl/towncrier
[Oasis Labs' towncrier fork]: https://github.com/oasislabs/towncrier
[style of Git commit messages]: ../CONTRIBUTING.md#git-commit-messages
