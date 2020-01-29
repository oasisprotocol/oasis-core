// Package tests contains genesis test helpers.
package tests

import (
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
)

// TestChainID is the chain ID that should be used in tests.
const TestChainID = "test: oasis-core tests"

// TestChainContext is the chain domain separation context that should
// be used in tests.
var TestChainContext string

// SetTestChainContext configures the TestChainID as the chain domain
// separation context.
func SetTestChainContext() {
	signature.SetChainContext(TestChainContext)
}

func init() {
	var chainContext hash.Hash
	// NOTE: This is not how the chain ID is actually derived, but we
	//       just use something similar for unit tests.
	chainContext.FromBytes([]byte(TestChainID))
	TestChainContext = chainContext.String()
}
