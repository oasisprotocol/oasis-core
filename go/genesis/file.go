package genesis

import (
	"encoding/json"
	"io/ioutil"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/genesis/api"
)

type fileProvider struct {
	document *api.Document
}

func (p *fileProvider) GetGenesisDocument() (*api.Document, error) {
	return p.document, nil
}

// NewFileProvider creates a new local file genesis provider.
func NewFileProvider(filename string) (api.Provider, error) {
	logger := logging.GetLogger("genesis/file")

	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		logger.Warn("failed to open genesis document",
			"err", err,
			"filename", filename,
		)
		return nil, err
	}

	var doc api.Document
	if err = json.Unmarshal(raw, &doc); err != nil {
		return nil, errors.Wrap(err, "genesis: malformed genesis file")
	}

	return &fileProvider{document: &doc}, nil
}
