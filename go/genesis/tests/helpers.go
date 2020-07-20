// Package tests contains genesis test helpers.
package tests

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

const (
	// TestChainID is the chain ID that should be used in tests.
	TestChainID = "test: oasis-core tests"

	// TestStakingTokenSymbol is the token's ticker symbol that should be used
	// in tests.
	TestStakingTokenSymbol = "TEST"
	// TestStakingTokenValueExponent is the token's value base-10 exponent that
	// should be used in tests.
	TestStakingTokenValueExponent uint8 = 6
)

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
