package genesis

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	// CfgNewGenesisFile is the flag used to specify a new genesis file.
	CfgNewGenesisFile = "genesis.new_file"

	cfgNewChainID = "genesis.new_chain_id"
)

var (
	migrateGenesisCmd = &cobra.Command{
		Use:   "migrate",
		Short: "migrate a genesis document from a previous release",
		Run:   doMigrateGenesis,
	}

	migrateGenesisFlags = flag.NewFlagSet("", flag.ContinueOnError)

	errOldNodeDesc = errors.New("deprecated node descriptor")
)

func doMigrateGenesis(cmd *cobra.Command, _ []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	// Load the old genesis document.
	f := flags.GenesisFile()
	raw, err := os.ReadFile(f)
	if err != nil {
		logger.Error("failed to open genesis file",
			"err", err,
		)
		os.Exit(1)
	}

	// Parse the genesis.
	var doc genesis.Document
	if err = json.Unmarshal(raw, &doc); err != nil {
		logger.Error("failed to parse old genesis file",
			"err", err,
		)
		os.Exit(1)
	}

	// Actually fix the genesis document.
	newDoc, err := updateGenesisDoc(doc)
	if err != nil {
		logger.Error("failed to fix genesis document",
			"err", err,
		)
		os.Exit(1)
	}

	// Validate the new genesis document.
	if err = newDoc.SanityCheck(); err != nil {
		logger.Warn("new genesis document sanity check failed",
			"err", err,
		)
	}

	// Write out the new genesis document.
	w, shouldClose, err := cmdCommon.GetOutputWriter(cmd, CfgNewGenesisFile)
	if err != nil {
		logger.Error("failed to get writer for fixed genesis file",
			"err", err,
		)
		os.Exit(1)
	}
	if shouldClose {
		defer w.Close()
	}
	canonJSON, err := newDoc.CanonicalJSON()
	if err != nil {
		logger.Error("failed to get canonical form of fixed genesis file",
			"err", err,
		)
		os.Exit(1)
	}
	if _, err = w.Write(canonJSON); err != nil {
		logger.Error("failed to write fixed genesis file",
			"err", err,
		)
		os.Exit(1)
	}
}

type oldNodeDesc struct {
	cbor.Versioned
	ID              signature.PublicKey `json:"id"`
	EntityID        signature.PublicKey `json:"entity_id"`
	Expiration      uint64              `json:"expiration"`
	TLS             node.TLSInfo        `json:"tls"`
	P2P             node.P2PInfo        `json:"p2p"`
	Consensus       node.ConsensusInfo  `json:"consensus"`
	VRF             *node.VRFInfo       `json:"vrf,omitempty"`
	Runtimes        []*node.Runtime     `json:"runtimes"`
	Roles           node.RolesMask      `json:"roles"`
	SoftwareVersion string              `json:"software_version,omitempty"`

	// The CBOR decoder is extra strict and will complain if this is
	// not defined, as it was removed.
	DeprecatedBeacon cbor.RawMessage `json:"beacon,omitempty"`
}

func openSignedNode(_ signature.Context, sn *node.MultiSignedNode) (*node.Node, error) {
	var (
		node node.Node
		err  error
	)
	if err = sn.Open(registry.RegisterGenesisNodeSignatureContext, &node); err == nil {
		return &node, nil
	}

	// See if it's puking because `DeprecatedBeacon` was removed.
	var oldNode oldNodeDesc
	if errErr := sn.MultiSigned.Open(registry.RegisterGenesisNodeSignatureContext, &oldNode); errErr == nil {
		logger.Warn("removing node as descriptor format is deprecated",
			"entity_id", oldNode.EntityID,
			"node_id", oldNode.ID,
		)
		return nil, errOldNodeDesc
	}

	return nil, fmt.Errorf("unable to open signed node: %w", err) // Original error
}

func updateGenesisDoc(oldDoc genesis.Document) (*genesis.Document, error) { //nolint: gocyclo
	// Create the new genesis document template.
	newDoc := oldDoc

	var err error

	// Fixup the burn address if needed.
	if err = fixupBurnAddress(&newDoc); err != nil {
		logger.Error("failed to fixup burn address", err)
		return nil, err
	}

	// Fix allowance if needed.
	for addr, acc := range newDoc.Staking.Ledger {
		for bene, allow := range acc.General.Allowances {
			if allow.Cmp(&newDoc.Staking.TotalSupply) > 0 {
				// Cap the maximum allowance to total supply.
				logger.Warn("limiting allowance to total supply", "address", addr, "beneficiary", bene, "old_amount", allow, "updated_amount", newDoc.Staking.TotalSupply)
				acc.General.Allowances[bene] = newDoc.Staking.TotalSupply
			}
		}
	}

	// Add global observer stake threshold (based on compute node threshold) if needed.
	if _, exists := newDoc.Staking.Parameters.Thresholds[staking.KindNodeObserver]; !exists {
		newDoc.Staking.Parameters.Thresholds[staking.KindNodeObserver] = newDoc.Staking.Parameters.Thresholds[staking.KindNodeCompute]
	}

	// Collect runtimes.
	knownRuntimes := make(map[common.Namespace]*registry.Runtime)
	for _, oldRt := range oldDoc.Registry.Runtimes {
		newRt := oldRt
		if _, exists := knownRuntimes[newRt.ID]; exists {
			return nil, fmt.Errorf("duplicate runtime %s", newRt.ID)
		}
		knownRuntimes[newRt.ID] = newRt
	}
	for _, oldRt := range oldDoc.Registry.SuspendedRuntimes {
		newRt := oldRt
		if _, exists := knownRuntimes[newRt.ID]; exists {
			return nil, fmt.Errorf("duplicate runtime %s", newRt.ID)
		}
		knownRuntimes[newRt.ID] = newRt
	}

	newDoc.Registry.Entities = make([]*entity.SignedEntity, 0)
	newDoc.Registry.Nodes = make([]*node.MultiSignedNode, 0)

	// Remove entities with not enough stake.
	var entities []*entity.Entity
	var nodes []*node.Node
	var runtimes []*registry.Runtime
	for _, sigEntity := range oldDoc.Registry.Entities {
		var entity entity.Entity
		if err = sigEntity.Open(registry.RegisterGenesisEntitySignatureContext, &entity); err != nil {
			return nil, fmt.Errorf("unable to open signed entity: %w", err)
		}
		entities = append(entities, &entity)
	}
	for _, sigNode := range oldDoc.Registry.Nodes {
		var node *node.Node
		node, err = openSignedNode(registry.RegisterGenesisNodeSignatureContext, sigNode)
		if err != nil {
			if errors.Is(err, errOldNodeDesc) {
				continue
			}
			return nil, err
		}
		nodes = append(nodes, node)
	}
	runtimes = append(runtimes, newDoc.Registry.Runtimes...)
	runtimes = append(runtimes, newDoc.Registry.SuspendedRuntimes...)

	generatedEscrows, err := computeStakeClaims(
		entities,
		nodes,
		runtimes,
		newDoc.Staking.Ledger,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to compute stake claims: %w", err)
	}

	removedEntities := make(map[signature.PublicKey]*entity.Entity)
	entityMap := make(map[signature.PublicKey]*entity.Entity)
	for _, sigEntity := range oldDoc.Registry.Entities {
		var entity entity.Entity
		if err = sigEntity.Open(registry.RegisterEntitySignatureContext, &entity); err != nil {
			return nil, fmt.Errorf("unable to open signed entity: %w", err)
		}
		addr := staking.NewAddress(entity.ID)
		escrowAcc := generatedEscrows[addr]
		if escrowAcc == nil {
			// Entity cannot pass stake claims, drop entity.
			logger.Warn("removing entity not passing stake claims: no account in ledger",
				"entity_id", entity.ID,
			)
			removedEntities[entity.ID] = &entity
			continue
		}

		if err = escrowAcc.CheckStakeClaims(newDoc.Staking.Parameters.Thresholds); err != nil {
			logger.Warn("removing entity not passing stake claims",
				"entity_id", entity.ID,
				"err", err,
			)
			removedEntities[entity.ID] = &entity
			continue
		}
		newDoc.Registry.Entities = append(newDoc.Registry.Entities, sigEntity)
		entityMap[entity.ID] = &entity
	}
NodeLoop:
	for _, sigNode := range oldDoc.Registry.Nodes {
		var node *node.Node
		node, err = openSignedNode(registry.RegisterGenesisNodeSignatureContext, sigNode)
		if err != nil {
			if errors.Is(err, errOldNodeDesc) {
				continue
			}
			return nil, err
		}
		if ent := removedEntities[node.EntityID]; ent != nil {
			logger.Warn("removing node as owning entity doesn't pass stake claims",
				"entity_id", node.EntityID,
				"node_id", node.ID,
			)
			continue
		}
		if !entityMap[node.EntityID].HasNode(node.ID) {
			logger.Warn("removing node as owning entity does not have it in its whitelist",
				"entity_id", node.EntityID,
				"node_id", node.ID,
			)
			continue
		}
		if err = node.ValidateBasic(false); err != nil {
			logger.Warn("removing node not passing basic validation check",
				"err", err,
				"node_id", node.ID,
			)
			continue
		}
		for _, rt := range node.Runtimes {
			_, exists := knownRuntimes[rt.ID]
			if !exists {
				logger.Warn("removing node referencing unknown runtime",
					"node_id", node.ID,
					"runtime_id", rt.ID,
				)
				continue NodeLoop
			}
		}
		newDoc.Registry.Nodes = append(newDoc.Registry.Nodes, sigNode)
	}

	// Move key manager gas costs from the registry to the key manager.
	newDoc.KeyManager.Parameters.GasCosts = keymanager.DefaultGasCosts
	newDoc.KeyManager.Parameters.GasCosts[keymanager.GasOpUpdatePolicy] = newDoc.Registry.Parameters.GasCosts["update_keymanager"]
	delete(newDoc.Registry.Parameters.GasCosts, "update_keymanager")

	// Update registry parameters.
	newDoc.Registry.Parameters.TEEFeatures = &node.TEEFeatures{
		SGX: node.TEEFeaturesSGX{
			PCS:                      true,
			SignedAttestations:       true,
			DefaultMaxAttestationAge: 1200, // ~2 hours at 6 sec per block.
		},
		FreshnessProofs: true,
	}
	newDoc.Registry.Parameters.GasCosts[registry.GasOpProveFreshness] = registry.DefaultGasCosts[registry.GasOpProveFreshness]
	newDoc.Registry.Parameters.MaxRuntimeDeployments = 5

	// Update governance parameters.
	newDoc.Governance.Parameters.EnableChangeParametersProposal = true

	// Automatically update the chain ID and base epoch when set.
	if newChainID := viper.GetString(cfgNewChainID); newChainID != "" {
		newDoc.ChainID = newChainID
		newDoc.Beacon.Base++

		// Update extra data to be as specified in the initial network genesis block.
		newDoc.ExtraData = map[string][]byte{
			"quote": []byte("Quis custodiet ipsos custodes? [submitted by Oasis Community Member Daniyar Borangaziyev]"),
		}
	}

	// Add a sensible default for the MaxPastRootsStored parameter.
	newDoc.RootHash.Parameters.MaxPastRootsStored = 1200

	// Update runtime parameters.
	rts := make([]*registry.Runtime, 0, len(newDoc.Registry.Runtimes)+len(newDoc.Registry.SuspendedRuntimes))
	rts = append(rts, newDoc.Registry.Runtimes...)
	rts = append(rts, newDoc.Registry.SuspendedRuntimes...)

	for _, rt := range rts {
		if !rt.IsCompute() {
			continue
		}
		rt.TxnScheduler.ProposerTimeout = 5 * time.Second
		if rt.TxnScheduler.BatchFlushTimeout > rt.TxnScheduler.ProposerTimeout {
			rt.TxnScheduler.ProposerTimeout = rt.TxnScheduler.BatchFlushTimeout
		}
	}

	// Reduce maximum consensus layer block size.
	newDoc.Consensus.Parameters.MaxBlockSize = 1_048_576 // 1 MiB

	return &newDoc, nil
}

func computeStakeClaims(
	entities []*entity.Entity,
	nodes []*node.Node,
	runtimes []*registry.Runtime,
	accounts map[staking.Address]*staking.Account,
) (map[staking.Address]*staking.EscrowAccount, error) {
	computedStakeClaims := make(map[staking.Address]*staking.EscrowAccount)

	// Entity accounts.
	for _, entity := range entities {
		addr := staking.NewAddress(entity.ID)
		acc := accounts[addr]
		accumulator := staking.StakeAccumulator{
			Claims: make(map[staking.StakeClaim][]staking.StakeThreshold),
		}
		accumulator.AddClaimUnchecked(registry.StakeClaimRegisterEntity, staking.GlobalStakeThresholds(staking.KindEntity))
		computedStakeClaims[addr] = &staking.EscrowAccount{
			Active:           acc.Escrow.Active,
			StakeAccumulator: accumulator,
		}
	}

	// Runtime accounts.
	runtimeMap := make(map[common.Namespace]*registry.Runtime)
	for _, rt := range runtimes {
		runtimeMap[rt.ID] = rt

		if rt.GovernanceModel == registry.GovernanceRuntime {
			addr := staking.NewRuntimeAddress(rt.ID)
			acc := accounts[addr]
			accumulator := staking.StakeAccumulator{
				Claims: make(map[staking.StakeClaim][]staking.StakeThreshold),
			}
			computedStakeClaims[addr] = &staking.EscrowAccount{
				Active:           acc.Escrow.Active,
				StakeAccumulator: accumulator,
			}
		}
	}

	// Node stake claims.
	for _, node := range nodes {
		var nodeRts []*registry.Runtime
		for _, rt := range node.Runtimes {
			nodeRts = append(nodeRts, runtimeMap[rt.ID])
		}
		addr := staking.NewAddress(node.EntityID)
		computedStakeClaims[addr].StakeAccumulator.AddClaimUnchecked(registry.StakeClaimForNode(node.ID), registry.StakeThresholdsForNode(node, nodeRts))
	}

	// Runtime stake claims.
	for _, rt := range runtimes {
		addr := rt.StakingAddress()
		if addr == nil {
			continue
		}

		computedStakeClaims[*addr].StakeAccumulator.AddClaimUnchecked(registry.StakeClaimForRuntime(rt.ID), registry.StakeThresholdsForRuntime(rt))
	}

	return computedStakeClaims, nil
}

func fixupBurnAddress(newDoc *genesis.Document) error {
	// The burn address was added after the fact, and it is possible
	// interact with it prematurely in several ways.
	burnAccount := newDoc.Staking.Ledger[staking.BurnAddress]
	if burnAccount == nil {
		// The burn address does not have a corresponding ledger entry
		// so there is nothing to fix.
		return nil
	}

	logger.Warn("burn address has an exiting ledger entry",
		"account", burnAccount,
	)

	// Check for signs that someone happened to generate the private key.
	if burnAccount.General.Nonce != 0 || len(burnAccount.General.Allowances) != 0 {
		// It looks like someone has the private key to the burn address.
		//
		// This is unlikely in the extreme but possible, in which case we
		// need	to generate a new burn address since we aren't in the
		// business of obliterating user tokens.
		return fmt.Errorf("burn address ledger entry looks used")
	}

	// Ok.  The private key is presumably unknown, people probably transferred
	// tokens to the address prematurely or something.
	if balance := burnAccount.General.Balance; balance.IsZero() {
		// If the general balance is non-zero, burn it off.
		logger.Warn("burn address has existing balance, BURNING",
			"balance", balance,
		)
		if err := newDoc.Staking.TotalSupply.Sub(&balance); err != nil {
			return fmt.Errorf("staking: failed to reduce total supply: %w", err)
		}
		_ = burnAccount.General.Balance.FromUint64(0)
	}

	// The EscrowAccount is ignored as users that happened to have delegated
	// to reserved addresses are allowed to undelegate.  The genesis document
	// sanity checks, do nothing special for reserved addresses as well.

	return nil
}

func init() {
	migrateGenesisFlags.String(CfgNewGenesisFile, "genesis_new.json", "path to migrated genesis document")
	migrateGenesisFlags.String(cfgNewChainID, "", "optional new chain ID")
	_ = viper.BindPFlags(migrateGenesisFlags)
}
