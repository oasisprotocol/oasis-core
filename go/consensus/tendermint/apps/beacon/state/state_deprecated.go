// Package state is deprecated.
package state

import "github.com/oasisprotocol/oasis-core/go/common/keyformat"

//nolint:deadcode,unused,varcheck
var (
	// deprecatedPvssStateKeyFmt is the current PVSS round key format.
	deprecatedPvssStateKeyFmt = keyformat.New(0x44)
	// deprecatedPvssPendingMockEpochKeyFmt is the pending mock epoch key format.
	deprecatedPvssPendingMockEpochKeyFmt = keyformat.New(0x45)
)
