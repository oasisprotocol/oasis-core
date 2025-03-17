// Package file implements a file genesis provider.
package file

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/genesis/api"
)

// fileProvider provides the static genesis document that network was
// initialized with.
type fileProvider struct {
	document *api.Document
}

func (p *fileProvider) GetGenesisDocument() (*api.Document, error) {
	return p.document, nil
}

// DefaultFileProvider creates a new local file genesis provider for the genesis file path
// specified in the genesis config.
func DefaultFileProvider() (api.Provider, error) {
	return NewFileProvider(config.GlobalConfig.Genesis.File)
}

// NewFileProvider creates a new local file genesis provider.
func NewFileProvider(filename string) (api.Provider, error) {
	logger := logging.GetLogger("genesis/file").With("filename", filename)

	raw, err := os.ReadFile(filename)
	if err != nil {
		logger.Warn("failed to open genesis document",
			"err", err,
		)
		return nil, err
	}

	var doc api.Document
	if err = json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("genesis: malformed genesis file: %w", err)
	}

	if err = doc.SanityCheck(); err != nil {
		return nil, fmt.Errorf("genesis: bad genesis file: %w", err)
	}

	return &fileProvider{document: &doc}, nil
}
