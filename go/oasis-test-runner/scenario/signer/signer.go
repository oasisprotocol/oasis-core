// Package signer implements the common signer test cases.
package signer

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

// BasicTests ensures basic signer factory sanity.
//
// Note: The factory must be configured to service signature.SignerRoles.
func BasicTests(factory signature.SignerFactory, logger *logging.Logger, roles []signature.SignerRole) error {
	// EnsureRole()
	logger.Info("testing EnsureRole")
	for _, v := range roles {
		if err := factory.EnsureRole(v); err != nil {
			return fmt.Errorf("failed to EnsureRole(%v): %w", v, err)
		}
	}

	msg := []byte("You have my thanks, hacker. Let me show you the destruction you have brought upon the planet Earth.")

	// Test each sub-key.
	pkMap := make(map[signature.PublicKey]bool)
	for _, v := range roles {
		// Load()
		si, err := factory.Load(v)
		if err != nil {
			return fmt.Errorf("failed to Load(%v): %w", v, err)
		}

		pk := si.Public()
		logger.Info("signer sub-key loaded",
			"public_key", pk,
			"descr", si.String(),
		)

		// ContextSign()
		ctx := signature.NewContext(fmt.Sprintf("plugin test context: %v", v))
		sig, err := si.ContextSign(ctx, msg)
		if err != nil {
			return fmt.Errorf("failed to Sign(%v): %w", v, err)
		}

		// Verify that the signature is sensible.
		if !pk.Verify(ctx, msg, sig) {
			return fmt.Errorf("failed to verify signature: %v", v)
		}

		pkMap[pk] = true
	}

	// Ensure that the signer uses unique sub-keys.
	if len(pkMap) != len(roles) {
		return fmt.Errorf("signer not using unique public keys: %v distinct found", len(pkMap))
	}

	return nil
}
