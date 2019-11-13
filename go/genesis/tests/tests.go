package tests

import "github.com/oasislabs/oasis-core/go/common/crypto/signature"

// TestChainID is the chain ID that should be used in tests.
const TestChainID = "test: oasis-core tests"

// SetTestChainContext configures the TestChainID as the chain domain
// separation context.
func SetTestChainContext() {
	signature.SetChainContext(TestChainID)
}
