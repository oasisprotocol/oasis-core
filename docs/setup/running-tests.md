# Running Tests

Before proceeding, make sure to look at the [prerequisites] required for running
an Oasis Core environment followed by [build instructions] for the respective
environment (non-SGX or SGX). The following sections assume that you have
successfully completed the required build steps.

[prerequisites]: prerequisites.md
[build instructions]: building.md

## Tests

After you've built everything, you can use the following commands to run tests.

To run all unit tests:

```
make test-unit
```

To run end-to-end tests locally:

```
make test-e2e
```

To run all tests:

```
make test
```

To execute tests using SGX set the following environmental variable before
running the tests:

```
export OASIS_TEE_HARDWARE=intel-sgx
```

## Troubleshooting

Check the console output for mentions of a path of the form
`/tmp/oasis-test-runnerXXXXXXXXX` (where each `X` is a digit).
That's the log directory. Start with coarsest-level debug output in
`console.log` files:

```
cat $(find /tmp/oasis-test-runnerXXXXXXXXX -name console.log) | less
```

For even more output, check the other `*.log` files.
