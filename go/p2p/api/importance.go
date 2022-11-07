package api

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
)

const peerTagImportancePrefix = "oasis-core/importance"

// ImportanceKind is the node importance kind.
type ImportanceKind uint8

const (
	ImportantNodeCompute    = 1
	ImportantNodeKeyManager = 2
)

// Tag returns the connection manager tag associated with the given importance kind.
func (ik ImportanceKind) Tag(runtimeID common.Namespace) string {
	switch ik {
	case ImportantNodeCompute:
		return peerTagImportancePrefix + "/compute/" + runtimeID.String()
	case ImportantNodeKeyManager:
		return peerTagImportancePrefix + "/keymanager/" + runtimeID.String()
	default:
		panic(fmt.Errorf("unsupported tag: %d", ik))
	}
}

// TagValue returns the connection manager tag value associated with the given importance kind.
func (ik ImportanceKind) TagValue() int {
	switch ik {
	case ImportantNodeCompute, ImportantNodeKeyManager:
		return 1000
	default:
		panic(fmt.Errorf("unsupported tag: %d", ik))
	}
}
