package tendermint

import (
	"encoding/json"
	"time"

	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/identity"
	genesis "github.com/oasislabs/ekiden/go/genesis/api"
	"github.com/oasislabs/ekiden/go/tendermint/crypto"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

var _ service.GenesisProvider = (*singleNodeGenesisProvider)(nil)

type singleNodeGenesisProvider struct {
	document   *genesis.Document
	tmDocument *tmtypes.GenesisDoc
}

func (p *singleNodeGenesisProvider) GetGenesisDocument() (*genesis.Document, error) {
	return p.document, nil
}

func (p *singleNodeGenesisProvider) GetTendermintGenesisDocument() (*tmtypes.GenesisDoc, error) {
	return p.tmDocument, nil
}

// NewSingleNodeGenesisProvider creates a synthetic genesis document for
// running a single node "network", primarily for testing.
func NewSingleNodeGenesisProvider(identity *identity.Identity) (genesis.Provider, error) {
	doc := &genesis.Document{
		Time: time.Now(),
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	tmDoc := &tmtypes.GenesisDoc{
		ChainID:         "ekiden-test-chain",
		GenesisTime:     doc.Time,
		ConsensusParams: tmtypes.DefaultConsensusParams(),
		AppState:        b,
	}

	nodeID := identity.NodeSigner.Public()
	pk := crypto.PublicKeyToTendermint(&nodeID)
	validator := tmtypes.GenesisValidator{
		Address: pk.Address(),
		PubKey:  pk,
		Power:   1,
		Name:    "ekiden-test-validator-" + nodeID.String(),
	}

	tmDoc.Validators = append(tmDoc.Validators, validator)

	return &singleNodeGenesisProvider{
		document:   doc,
		tmDocument: tmDoc,
	}, nil
}
