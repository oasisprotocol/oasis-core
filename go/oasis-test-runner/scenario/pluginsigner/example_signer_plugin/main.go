// Package main implements an example oasis-node signer plugin.
package main

import (
	"crypto/rand"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	pluginSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/plugin"
)

type examplePlugin struct {
	roles []signature.SignerRole
	inner map[signature.SignerRole]signature.Signer
}

func (pl *examplePlugin) Initialize(config string, roles ...signature.SignerRole) error {
	// A real plugin will probably want to check to see if it has
	// already been initialized.

	pl.roles = roles
	pl.inner = make(map[signature.SignerRole]signature.Signer)

	return nil
}

func (pl *examplePlugin) Load(role signature.SignerRole, mustGenerate bool) error {
	if signer := pl.inner[role]; signer != nil {
		if mustGenerate {
			return fmt.Errorf("example: key already exists")
		}
		return nil
	}
	if !mustGenerate {
		return signature.ErrNotExist
	}

	signer, err := memorySigner.NewSigner(rand.Reader)
	if err != nil {
		return fmt.Errorf("example: failed to generate key: %w", err)
	}

	pl.inner[role] = signer

	return nil
}

func (pl *examplePlugin) Public(role signature.SignerRole) (signature.PublicKey, error) {
	signer := pl.inner[role]
	if signer == nil {
		return signature.PublicKey{}, signature.ErrNotExist
	}
	return signer.Public(), nil
}

func (pl *examplePlugin) ContextSign(role signature.SignerRole, rawContext signature.Context, message []byte) ([]byte, error) {
	signer, ok := pl.inner[role]
	if !ok {
		return nil, signature.ErrNotExist
	}
	return signer.ContextSign(rawContext, message)
}

func main() {
	// Signer plugins use raw contexts.
	signature.UnsafeAllowUnregisteredContexts()

	var impl examplePlugin
	pluginSigner.Serve("example", &impl)
}
