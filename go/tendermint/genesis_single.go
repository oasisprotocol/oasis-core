package tendermint

import (
	"encoding/json"
	"time"

	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/identity"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	"github.com/oasislabs/oasis-core/go/tendermint/crypto"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
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
		ChainID:         "oasis-test-chain",
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
		Name:    "oasis-test-validator-" + nodeID.String(),
	}

	tmDoc.Validators = append(tmDoc.Validators, validator)

	return &singleNodeGenesisProvider{
		document:   doc,
		tmDocument: tmDoc,
	}, nil
}
