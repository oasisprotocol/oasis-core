package tendermint

import (
	"encoding/json"
	"math"
	"time"

	tmtypes "github.com/tendermint/tendermint/types"

	consensus "github.com/oasislabs/oasis-core/go/common/consensus/genesis"
	"github.com/oasislabs/oasis-core/go/common/identity"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	stakingTests "github.com/oasislabs/oasis-core/go/staking/tests"
	tendermint "github.com/oasislabs/oasis-core/go/tendermint/api"
	"github.com/oasislabs/oasis-core/go/tendermint/crypto"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
	"github.com/oasislabs/oasis-core/go/worker/txnscheduler/algorithm/batching"
)

var _ service.GenesisProvider = (*testNodeGenesisProvider)(nil)

type testNodeGenesisProvider struct {
	document   *genesis.Document
	tmDocument *tmtypes.GenesisDoc
}

func (p *testNodeGenesisProvider) GetGenesisDocument() (*genesis.Document, error) {
	return p.document, nil
}

func (p *testNodeGenesisProvider) GetTendermintGenesisDocument() (*tmtypes.GenesisDoc, error) {
	return p.tmDocument, nil
}

// NewTestNodeGenesisProvider creates a synthetic genesis document for
// running a single node "network", only for testing.
func NewTestNodeGenesisProvider(identity *identity.Identity) (genesis.Provider, error) {
	doc := &genesis.Document{
		ChainID:   "oasis-test-chain",
		Time:      time.Now(),
		HaltEpoch: epochtime.EpochTime(math.MaxUint64),
		EpochTime: epochtime.Genesis{
			Parameters: epochtime.ConsensusParameters{
				DebugMockBackend: true,
			},
		},
		Registry: registry.Genesis{
			Parameters: registry.ConsensusParameters{
				DebugAllowUnroutableAddresses: true,
				DebugAllowRuntimeRegistration: true,
				DebugBypassStake:              true,
			},
		},
		RootHash: roothash.Genesis{
			Parameters: roothash.ConsensusParameters{
				RoundTimeout: 1 * time.Second,
				TransactionScheduler: roothash.TransactionSchedulerParameters{
					Algorithm:         batching.Name,
					BatchFlushTimeout: 1 * time.Second,
					MaxBatchSize:      10,
					MaxBatchSizeBytes: 16 * 1024 * 1024,
				},
			},
		},
		Scheduler: scheduler.Genesis{
			Parameters: scheduler.ConsensusParameters{
				MinValidators:            1,
				MaxValidators:            100,
				ValidatorEntityThreshold: 100,
				DebugBypassStake:         true,
				DebugStaticValidators:    true,
			},
		},
		Consensus: consensus.Genesis{
			Backend:           tendermint.BackendName,
			TimeoutCommit:     1 * time.Millisecond,
			SkipTimeoutCommit: true,
		},
		Staking: stakingTests.DebugGenesisState,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	tmDoc := &tmtypes.GenesisDoc{
		ChainID:         doc.ChainID,
		GenesisTime:     doc.Time,
		ConsensusParams: tmtypes.DefaultConsensusParams(),
		AppState:        b,
	}

	nodeID := identity.ConsensusSigner.Public()
	pk := crypto.PublicKeyToTendermint(&nodeID)
	validator := tmtypes.GenesisValidator{
		Address: pk.Address(),
		PubKey:  pk,
		Power:   1,
		Name:    "oasis-test-validator-" + nodeID.String(),
	}

	tmDoc.Validators = append(tmDoc.Validators, validator)

	return &testNodeGenesisProvider{
		document:   doc,
		tmDocument: tmDoc,
	}, nil
}
