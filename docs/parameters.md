# System parameters

This document describes the various system parameters that can be changed during
runtime and affect how the system behaves and its performance.

## Compute node

* `max-batch-size`: Determines the maximum size of a batch (in the number of
  transactions).
* `max-batch-timeout`: Determines the maximum time for a consensus to wait before
  trying to construct a new batch from the incoming queue.
