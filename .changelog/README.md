# Change Log fragments

This directory collects Change Log fragments:
short files that each contain a snippet of MarkDown formatted text that will be
assembled using [towncrier] to form the [Change Log] section for the next
release.

## Description

A Change Log fragment should be a description of aspects of the change (if any)
that are relevant to users.

_NOTE: This could be very different from the commit message and pull request
description, which are a description of the change as relevant to the people
working on the code itself._

The description could use one of the following two formats:

- One line change summary followed by an empty line and a more detailed
  explanation in the body.

  For example:

  ```text
  Remove staking-related roothash messages.

  There is no longer a plan to support direct manipulation of the staking accounts
  from the runtimes in order to isolate the runtimes from corrupting the
  consensus layer.

  To reduce complexity, the staking-related roothash messages were removed. The
  general roothash message mechanism stayed as-is since it may be useful in the
  future, but any commits with non-empty messages are rejected for now.
  ```

- Shorter multi-line change description.

  For example:

  ```text
  Add `oasis-node unsafe-reset` sub-command which resets the node back to a
  freshly provisioned state, preserving any key material if it exists.
  ```

_NOTE: Don't put links to issue(s)/pull request in your text as the [towncrier]
tool will add them automatically._

## File name

Each file should be named like `<ISSUE>.<TYPE>.md`, where `<ISSUE>` is a GitHub
issue or pull request number, and `<TYPE>` is one of:

- `process`: a change in Oasis Core's processes (e.g. development process,
  release process, ...),
- `breaking`: a removal of functionality or a breaking change,
- `feature`: a new feature,
- `bugfix`: a bug fix,
- `doc`: a documentation-related change,
- `trivial`: a trivial change that is _not_ included in the Change Log.

For example: ``1234.feature.md`` or ``2345.bugfix.md``.

If your pull requests closes an issue, use that number here.
If there is no issue for the change you've implemented, then after you submit
the pull request and get your pull request number, amend your commit(s) with an
appropriately named Change Log fragment.

## Render Change Log preview

To get a preview of how your change (and other changes queued up in this
directory) will look in the Change Log, install [Oasis Labs' towncrier fork]
with:

```bash
pip3 install https://github.com/oasislabs/towncrier/archive/oasis-master.tar.gz
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
