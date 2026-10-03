package genesis_test

import (
	"testing"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/stretchr/testify/assert"
)

func TestSanityCheck(t *testing.T) {
	// Helper to temporarily enable DebugDontBlameOasis and reset it after testing.
	defer flags.DebugDontBlameOasis()

	// Helper to create a valid Genesis object.
	newValidGenesis := func() *genesis.Genesis {
		return &genesis.Genesis{
			Backend: "test",
			Parameters: genesis.Parameters{
				TimeoutCommit:            1 * time.Second,
				SkipTimeoutCommit:        false,
				EmptyBlockInterval:       1 * time.Second,
				MaxTxSize:                1024,
				MaxBlockSize:             1024 * 1024,
				MaxBlockGas:              1000000,
				MaxEvidenceSize:          512,
				MinGasPrice:              1,
				StateCheckpointInterval:  1000,
				StateCheckpointNumKept:   1,
				StateCheckpointChunkSize: 1024 * 1024,
				GasCosts: transaction.Costs{
					genesis.GasOpTxByte: 1,
				},
				FeatureVersion: &version.Version{
					Major: 1,
					Minor: 0,
					Patch: 0,
				},
				PublicKeyBlacklist: []signature.PublicKey{},
			},
		}
	}

	tests := []struct {
		name       string
		modifyFunc func(*genesis.Genesis)
		expectErr  bool
	}{
		// Valid genesis object should pass the sanity check.
		{
			name:       "ValidGenesis",
			modifyFunc: func(g *genesis.Genesis) {},
			expectErr:  false,
		},
		// Invalid TimeoutCommit should fail the sanity check.
		{
			name: "InvalidTimeoutCommit",
			modifyFunc: func(g *genesis.Genesis) {
				g.Parameters.TimeoutCommit = 500 * time.Microsecond
				g.Parameters.SkipTimeoutCommit = false
			},
			expectErr: true,
		},
		// StateCheckpointInterval too low should fail.
		{
			name: "InvalidStateCheckpointInterval",
			modifyFunc: func(g *genesis.Genesis) {
				g.Parameters.StateCheckpointInterval = 999
			},
			expectErr: true,
		},
		// StateCheckpointNumKept is zero, should fail.
		{
			name: "InvalidStateCheckpointNumKept",
			modifyFunc: func(g *genesis.Genesis) {
				g.Parameters.StateCheckpointNumKept = 0
			},
			expectErr: true,
		},
		// StateCheckpointChunkSize too small, should fail.
		{
			name: "InvalidStateCheckpointChunkSize",
			modifyFunc: func(g *genesis.Genesis) {
				g.Parameters.StateCheckpointChunkSize = 512 * 1024
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			genesis := newValidGenesis()
			tt.modifyFunc(genesis)

			err := genesis.SanityCheck()
			if tt.expectErr {
				assert.Error(t, err, "expected an error but got none")
			} else {
				assert.NoError(t, err, "expected no error but got one")
			}
		})
	}
}
