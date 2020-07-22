// Package main implements an example oasis-node signer plugin, leveraging
// the Go runtime library's DSO plugin support.
package main

import (
	"fmt"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
)

// GetPluginCtor is the plugin's entry point.
func GetPluginCtor() signature.SignerFactoryCtor {
	return newPluginFactory
}

func newPluginFactory(config interface{}, roles ...signature.SignerRole) (signature.SignerFactory, error) {
	return &exampleFactory{
		roles: roles,
		inner: make(map[signature.SignerRole]signature.Signer),
	}, nil
}

type exampleFactory struct {
	roles []signature.SignerRole
	inner map[signature.SignerRole]signature.Signer
}

func (fac *exampleFactory) EnsureRole(role signature.SignerRole) error {
	for _, v := range fac.roles {
		if v == role {
			return nil
		}
	}
	return signature.ErrRoleMismatch
}

func (fac *exampleFactory) Generate(role signature.SignerRole, rng io.Reader) (signature.Signer, error) {
	if fac.inner[role] != nil {
		return nil, fmt.Errorf("example: key already exists")
	}

	signer, err := memorySigner.NewSigner(rng)
	if err != nil {
		return nil, fmt.Errorf("example: failed to generate key: %w", err)
	}

	fac.inner[role] = signer
	return signer, nil
}

func (fac *exampleFactory) Load(role signature.SignerRole) (signature.Signer, error) {
	if signer := fac.inner[role]; signer != nil {
		return signer, nil
	}
	return nil, signature.ErrNotExist
}
