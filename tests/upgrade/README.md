# Oasis Upgrade Tests

Oasis Upgrade Tests can be used to test seamless and dump/restore network
upgrades. The testing process involves taking an old and a new version
of the Oasis Core library, building binaries (such as oasis-node, runtimes,
keymanager, etc.), and using them to run upgrade tests.

Each upgrade test consists of two parts: the pre-upgrade scenario and
the post-upgrade scenario.

## Pre-upgrade scenario

The pre-upgrade scenario is an end-to-end scenario that is executed before
the actual upgrade takes place. Its main purpose is to prepare the network
for the upgrade and wait for the upgrade to occur.

For example, in a dump/restore upgrade test, the pre-upgrade scenario would
propose an upgrade proposal, vote for it, and wait for the network to halt.
It would then wipe the consensus state, keeping only the necessary runtime data,
key manager data, and runtime bundles required for the post-upgrade scenario.

Pre-upgrade scenarios rely on the code from the old version of the Oasis Core
library and are executed using binaries compiled from the same version.

## Post-upgrade scenario

The post-upgrade scenario is an end-to-end scenario that is executed after
the upgrade has taken place. This scenario does not start from scratch but
instead uses a copy of the data that was left after the pre-upgrade test
finished. Its main purpose is to test whether the old runtime binaries still
function correctly after the upgrade.

For example, in a dump/restore upgrade test, a post-upgrade scenario would
take the exported genesis file, make any necessary fixes, and use it to start
the network with the old runtime bundles.

Post-upgrade scenarios rely on the code from the new version of the Oasis Core
library and are executed using binaries compiled from the same version. However,
the scenario can still use the old runtime binaries if they were not deleted
by the pre-upgrade scenario.

## Running tests

The upgrade tests can be started by using the following command.

```bash
.buildkite/scripts/test_upgrade.sh
```

## Configure versions

To configure the old and new versions of the Oasis Core library used in
the upgrade tests, follow these steps:

1. Open the `./.buildkite/scripts/test_upgrade.sh` script file and modify values
`pre_upgrade_git_branch` and `post_upgrade_git_branch` accordingly.

2. Open the `./tests/upgrade/pre/go.mod` and `./tests/upgrade/post/go.mod`
files, and replace the Oasis Core module with the desired versions accordingly.

3. Fix tests if needed.

For example, if you want to test the stable/22.2.x branch against the master
branch, modify the following lines:

```bash
# Changes to file ./.buildkite/scripts/test_upgrade.sh.
pre_upgrade_git_branch="stable/22.2.x"
post_upgrade_git_branch="master"
```

```go
// Changes to file ./tests/upgrade/pre/go.mod.
require (
  github.com/oasisprotocol/oasis-core v22.2.9-0.20230504070346-a2f2268ff9e5+incompatible
)
```

```go
// Changes to file ./tests/upgrade/post/go.mod.
require (
  github.com/oasisprotocol/oasis-core v0.0.0-20230522081305-c96898af6ced
)
```

## Write tests

1. Write and register the pre-upgrade test scenario by placing the code in the
`./tests/upgrade/pre/scenario/e2e` folder.

2. Write and register the post-upgrade test scenario using the same scenario
name, and place the code in the `./tests/upgrade/post/scenario/e2e` folder.
