# Runtime IDs

Identifiers for runtimes, are represented by the `common.Namespace` type.

The first 64 bits are used to specify flags expressing various properties
of the runtime, the last 192 bits are used as the runtime identifier.

Currently the following flags are defined (bit positions assume the flags
vector is interpreted as an unsigned 64 bit big endian integer):

 * Bit 63: The runtime is a test runtime and not for production networks.
 * Bit 62: The runtime is a key manager runtime.
 * Bits 61-0: Reserved for future expansion and MUST be set to 0.

Note: Unless the registry consensus parameter `DebugAllowTestRuntimes` is
set, attempts to register a test runtime will be rejected.
