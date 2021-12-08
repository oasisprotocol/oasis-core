package state

import "github.com/oasisprotocol/oasis-core/go/common/keyformat"

// deprecatedBeaconPointMapKeyFmt is the key format used for
// the point-to-node-id-map.
//
var deprecatedBeaconPointMapKeyFmt = keyformat.New(0x1a, []byte{}) //nolint:deadcode,unused,varcheck
