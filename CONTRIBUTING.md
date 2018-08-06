# Contributing to Oasis Labs Repositories

Oasis Labs is building the next generation blockchain technology for scalable, privacy-preserving, and distributed applications/services.

Thank you for your interest in contributing to Oasis! There are many ways to contribute, and this document should not be considered encompassing. If you have questions, please file an issue in this repository.

#### Table of Contents

[Feature Requests](#feature-requests)

[Bug Reports](#bug-reports)

[Development](#development)
  * [Building](#building)
  * [Contributing Code](#contributing-code)
  * [Contributing Documentation](#contributing-documentation)
  * [Style Guides](#style-guides)
    * [Git Commit Messages](#git-commit-messages)
    * [Rust Styleguide](#rust-styleguide)
    * [Go Styleguide](#go-styleguide)

[Making a Release](#making-a-release)

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

More information about what we consider to be useful bug reports is included as prompts in our default [issue template](https://github.com/oasislabs/ekiden/issues/new).

## Development

### Building

Our development environment is documented in our main repository [README](https://github.com/oasislabs/ekiden/blob/master/README.md) documents.

### Contributing Code

* **File issues:** Please make sure there are GitHub issues filed for all work (planned, in-progress, or completed).
* **Create branches:** Use user-id prefixed branches (e.g. user/feature/foobar) for all development of new features and bug fixes.
  * Good habit: regularly rebase to the head of master to make sure you’re avoiding nasty conflicts:
    ```
    $ git rebase origin/master
    ```
  * Push your branch to GitHub regularly so others can see what you are working on:
    ```
    $ git push origin BRANCH_NAME
    ```
  * Note: You are allowed to force push into your development branches.
* **Create a "[WIP] Title" pull request**
  * The title signals that the code is not ready for review, but still gives a nice URL to track the ongoing work.
* *master* branch is protected and will require at least 1 code review approval before merges are approved.
* When coding, please follow these standard practices:
  * **Write tests:** Especially when fixing bugs, make a test so we know that we’ve fixed the bug and that we don’t break it again in the future.
  * **Logging:** Please follow the logging convention in the rest of the code base.
  * **Instrumentation:** Please following the instrumentation convention.
    * Try to instrument anything that would be relevant to an operational network.
* **Documentation:** Please write documentation in the code as you go in docs.rs format.
* **Update CHANGELOG:** Document changes in `CHANGELOG.md` in repository root, mark all backward incompatible changes with "BACKWARD INCOMPATIBLE" and put them at the top.
* **Check CI:** Don’t break the build!
  * Make sure all tests pass before submitting your pull request for review.
* **Signal PR review:**
  * Remove "[WIP]" from the PR title.
  * Please include good high-level descriptions of what the pull request does.
  * The description should include references to all GitHub issues addressed by the pull request. Include the status ("done", "partially done", etc).
  * Provide some details on how the code was tested.
  * After you are nearing review (and definitely before merge) **squash commits into logical parts** (avoid squashing over merged commits, use rebase first!). Use proper commit messages which explain what was changed in the given commit and why.
* **Get a code review:** You can generally look up the last few people to edit the file to get the best person to review.
  * When addressing the review: Make sure to address all comments, and respond to them so that the reviewer knows; e.g. with "done" or "acknowledged" or "I don't think so because ...".
* **Merge:** Once approved, the creator of the pull request should merge the branch, close the pull request, and delete the branch.
* **Signal to close issues:** Let the person who filed the issue close it. Ping them in a comment (e.g. @user) making sure you’ve commented how an issue was addressed.
  * Anyone else should be able to close the issue if not addressed within a week

### Contributing Documentation

Documentation is always welcome! Documentation comes in several forms:

* Code-level documentation, following language specifications.
* Mechanism documentation, which live in `docs/` describe commonly used systems, like adding a new protcol definiton, or benchmarking the system.
* Protocol documentation, living in the `RFCs` repository, describe protocols and architectural design.

### Style Guides

#### Git Commit Messages

A quick summary:

* Separate subject from body with a blank line.
* Limit the subject line to 50 characters.
* Capitalize the subject line.
* Do not end the subject line with a period.
* Use the present tense ("Add feature" not "Added feature").
* Use the imperative mood ("Move component to..." not "Moves component to...").
* Wrap the body at 72 characters.
* Use the body to explain what and why vs. how.

A detailed post on Git commit messages: [How To Write a Git Commit Message](https://chris.beams.io/posts/git-commit/).

#### Rust Styleguide

Rust code should use the style provided in the `.rustfmt.toml` in the top-level directory of the repository. Be sure to run `cargo fmt` before pushing any code.
`rustfmt` does not check import order, so please ensure that you use the following convention:
```rust
// extern crates
extern crate foo;

// mods
mod bar;

// std use
use std::{mem, box::Box};

// extern use
use foo::baz;

// mod use
use bar::quux;
```
Additionally, as `rustfmt` does not check `Cargo.toml`, please manually verify that changes to `Cargo.toml` follow the [best practices](https://github.com/rust-lang-nursery/fmt-rfcs/blob/master/guide/cargo.md) (the most important ones are sorting dependencies and splitting long lines).

#### Go Styleguide

Go code should use the standard `gofmt` formatting style. Be sure to run `gofmt` before pushing any code.

## Making a Release

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
