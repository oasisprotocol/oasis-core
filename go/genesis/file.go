package genesis

import (
	"io/ioutil"
	"os"
	"time"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
)

type fileProvider struct {
	document *Document
}

func (p *fileProvider) GetGenesisDocument() (*Document, error) {
	return p.document, nil
}

// NewFileProvider creates a new local file genesis provider.
func NewFileProvider(filename string, identity *identity.Identity) (Provider, error) {
	logger := logging.GetLogger("genesis/file")

	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// Genesis file does not exist, treat as a single-node validator.
			logger.Warn("Genesis file not present, running as a one-node validator",
				"filename", filename,
			)

			return &fileProvider{
				document: &Document{
					Time: time.Now(),
					Validators: []*Validator{
						{
							PubKey: identity.NodeKey.Public(),
							Name:   "ekiden-dummy",
							Power:  10,
						},
					},
				},
			}, nil
		}
		return nil, err
	}

	var doc Document
	if err = json.Unmarshal(raw, &doc); err != nil {
		return nil, errors.Wrap(err, "genesis: malformed genesis file")
	}

	return &fileProvider{document: &doc}, nil
}
