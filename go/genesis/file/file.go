// Package file implements a file genesis provider.
package file

import (
	"encoding/json"
	"io/ioutil"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/genesis/api"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
)

// fileProvider provides the static gensis document that network was
// initialized with.
type fileProvider struct {
	document *api.Document
}

func (p *fileProvider) GetGenesisDocument() (*api.Document, error) {
	return p.document, nil
}

// NewFileProvider creates a new local file genesis provider.
func NewFileProvider() (api.Provider, error) {
	filename := flags.GenesisFile()
	logger := logging.GetLogger("genesis/file").With("filename", filename)

	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		logger.Warn("failed to open genesis document",
			"err", err,
		)
		return nil, err
	}

	var doc api.Document
	if err = json.Unmarshal(raw, &doc); err != nil {
		return nil, errors.Wrap(err, "genesis: malformed genesis file")
	}

	return &fileProvider{document: &doc}, nil
}
