// Package file implements a file genesis provider.
package file

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/genesis/api"
)

// Provider provides the static genesis document that network was
// initialized with.
type Provider struct {
	filename string
}

// NewProvider creates a new local file genesis provider.
func NewProvider(filename string) *Provider {
	return &Provider{
		filename: filename,
	}
}

// GetGenesisDocument returns the genesis document.
func (p *Provider) GetGenesisDocument() (*api.Document, error) {
	raw, err := os.ReadFile(p.filename)
	if err != nil {
		return nil, fmt.Errorf("genesis: failed to open genesis document: %w", err)
	}

	var doc api.Document
	if err = json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("genesis: malformed genesis file: %w", err)
	}
	if err = doc.SanityCheck(); err != nil {
		return nil, fmt.Errorf("genesis: bad genesis file: %w", err)
	}

	return &doc, nil
}

// DefaultProvider creates a new local file genesis provider for the genesis file path
// specified in the genesis config.
func DefaultProvider() *Provider {
	return NewProvider(config.GlobalConfig.Genesis.File)
}
