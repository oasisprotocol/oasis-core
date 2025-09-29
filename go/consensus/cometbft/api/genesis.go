package api

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	cmttypes "github.com/cometbft/cometbft/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/crypto"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// GetCometBFTGenesisDocument returns the CometBFT genesis document corresponding to the Oasis
// genesis document specified by the given genesis provider.
func GetCometBFTGenesisDocument(d *genesis.Document) (*cmttypes.GenesisDoc, error) {
	// WARNING: The AppState MUST be encoded as JSON since its type is
	// json.RawMessage which requires it to be valid JSON. It may appear
	// to work until you try to restore from an existing data directory.
	//
	// The runtime library sorts map keys, so the output of json.Marshal
	// should be deterministic.
	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("cometbft: failed to serialize genesis doc: %w", err)
	}

	// Make sure that the initial height is at least 1 as required by CometBFT. This is ensured
	// early by the genesis document sanity checks, but let's be safe.
	if d.Height < 1 {
		return nil, fmt.Errorf("cometbft: invalid initial height (must be >=1): %d", d.Height)
	}

	// Translate special "disable block gas limit" value as CometBFT uses
	// -1 for some reason (as if a zero limit makes sense) and we use 0.
	maxBlockGas := int64(d.Consensus.Parameters.MaxBlockGas)
	if maxBlockGas == 0 {
		maxBlockGas = -1
	}

	// Automatically compute evidence parameters based on debonding period.
	debondingInterval := int64(d.Staking.Parameters.DebondingInterval)
	if debondingInterval == 0 && cmdFlags.DebugDontBlameOasis() {
		// Use a default of 1 epoch in case debonding is disabled and we are using debug mode. If
		// not in debug mode, this will just cause startup to fail which is good.
		debondingInterval = 1
	}
	var epochInterval int64
	switch d.Beacon.Parameters.Backend {
	case beacon.BackendInsecure:
		params := d.Beacon.Parameters.InsecureParameters
		epochInterval = params.Interval
		if epochInterval == 0 && cmdFlags.DebugDontBlameOasis() && d.Beacon.Parameters.DebugMockBackend {
			// Use a default of 100 blocks in case epoch interval is unset
			// and we are using debug mode.
			epochInterval = 100
		}
	case beacon.BackendVRF:
		params := d.Beacon.Parameters.VRFParameters
		epochInterval = params.Interval
		if epochInterval == 0 && cmdFlags.DebugDontBlameOasis() && d.Beacon.Parameters.DebugMockBackend {
			// Use a default of 100 blocks in case epoch interval is unset
			// and we are using debug mode.
			epochInterval = 100
		}
	default:
		return nil, fmt.Errorf("cometbft: unknown beacon backend: '%s'", d.Beacon.Parameters.Backend)
	}
	if epochInterval == 0 {
		return nil, fmt.Errorf("cometbft: unable to determine epoch interval")
	}

	var evCfg cmttypes.EvidenceParams
	evCfg.MaxBytes = int64(d.Consensus.Parameters.MaxEvidenceSize)
	evCfg.MaxAgeNumBlocks = debondingInterval * epochInterval
	evCfg.MaxAgeDuration = time.Duration(evCfg.MaxAgeNumBlocks) * (d.Consensus.Parameters.TimeoutCommit + 1*time.Second)

	doc := cmttypes.GenesisDoc{
		ChainID:       CometBFTChainID(d.ChainContext()),
		GenesisTime:   d.Time,
		InitialHeight: d.Height,
		ConsensusParams: &cmttypes.ConsensusParams{
			Block: cmttypes.BlockParams{
				MaxBytes: int64(d.Consensus.Parameters.MaxBlockSize),
				MaxGas:   maxBlockGas,
			},
			Evidence: evCfg,
			Validator: cmttypes.ValidatorParams{
				PubKeyTypes: []string{cmttypes.ABCIPubKeyTypeEd25519},
			},
			Version: cmttypes.VersionParams{
				App: version.CometBFTAppVersion,
			},
		},
		AppState: b,
	}

	doc.Validators, err = convertValidators(d)
	if err != nil {
		return nil, err
	}

	return &doc, nil
}

// convertValidators converts validators into CometBFT format.
func convertValidators(d *genesis.Document) ([]cmttypes.GenesisValidator, error) {
	var err error
	var tmValidators []cmttypes.GenesisValidator
	vPerE := make(map[signature.PublicKey]int)
	for _, v := range d.Registry.Nodes {
		var openedNode node.Node
		if err = v.Open(registry.RegisterGenesisNodeSignatureContext, &openedNode); err != nil {
			return nil, fmt.Errorf("cometbft: failed to verify validator: %w", err)
		}
		// TODO: This should cross check that the entity is valid.
		if !openedNode.HasRoles(node.RoleValidator) {
			continue
		}

		// Skip expired nodes.
		if openedNode.IsExpired(d.Beacon.Base) {
			continue
		}

		// Calculate voting power from stake.
		var power int64
		if d.Scheduler.Parameters.DebugBypassStake {
			power = 1
		} else {
			var stake *quantity.Quantity
			acctAddr := staking.NewAddress(openedNode.EntityID)
			if account, ok := d.Staking.Ledger[acctAddr]; ok {
				stake = account.Escrow.Active.Balance.Clone()
			} else {
				// If all balances and stuff are zero, it's permitted not to
				// have an account in the ledger at all.
				stake = &quantity.Quantity{}
			}
			power, err = scheduler.VotingPowerFromStake(stake, d.Scheduler.Parameters.VotingPowerDistribution)
			if err != nil {
				return nil, fmt.Errorf("cometbft: computing voting power for entity %s with account %s and stake %v: %w",
					openedNode.EntityID,
					acctAddr,
					stake,
					err,
				)
			}
		}

		// Make sure that the number of validators per entity stays under
		// the MaxValidatorsPerEntity limit.
		if numV, exists := vPerE[openedNode.EntityID]; exists {
			if numV >= d.Scheduler.Parameters.MaxValidatorsPerEntity {
				continue
			}
			vPerE[openedNode.EntityID] = numV + 1
		} else {
			vPerE[openedNode.EntityID] = 1
		}

		pk := crypto.PublicKeyToCometBFT(&openedNode.Consensus.ID)
		validator := cmttypes.GenesisValidator{
			Address: pk.Address(),
			PubKey:  pk,
			Power:   power,
			Name:    "oasis-validator-" + openedNode.ID.String(),
		}
		tmValidators = append(tmValidators, validator)
	}

	// Sort validators by power in descending order.
	sort.Slice(tmValidators, func(i, j int) bool {
		return tmValidators[i].Power > tmValidators[j].Power
	})

	// Keep only the first MaxValidators validators.
	maxVal := min(d.Scheduler.Parameters.MaxValidators, len(tmValidators))
	return tmValidators[:maxVal], nil
}
