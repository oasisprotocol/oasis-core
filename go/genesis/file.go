package genesis

import (
	"io/ioutil"
	"os"
	"time"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/genesis/api"
)

type fileProvider struct {
	document *api.Document
}

func (p *fileProvider) GetGenesisDocument() (*api.Document, error) {
	return p.document, nil
}

// NewFileProvider creates a new local file genesis provider.
func NewFileProvider(filename string, identity *identity.Identity) (api.Provider, error) {
	logger := logging.GetLogger("genesis/file")

	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// Genesis file does not exist, treat as a single-node validator.
			logger.Warn("Genesis file not present, running as a one-node validator",
				"filename", filename,
			)

			entity, signer, _, _ := entity.TestEntity()
			validator := &api.Validator{
				EntityID: entity.ID,
				PubKey:   identity.NodeSigner.Public(),
				Name:     "ekiden-dummy",
				Power:    10,
			}

			// TODO: This should use subSigners[entity.SubkeyNodeRegistration]
			signedValidator, sigErr := api.SignValidator(signer, validator)
			if sigErr != nil {
				return nil, sigErr
			}

			return &fileProvider{
				document: &api.Document{
					Time:       time.Now(),
					Validators: []*api.SignedValidator{signedValidator},
				},
			}, nil
		}
		return nil, err
	}

	var doc api.Document
	if err = json.Unmarshal(raw, &doc); err != nil {
		return nil, errors.Wrap(err, "genesis: malformed genesis file")
	}

	return &fileProvider{document: &doc}, nil
}
