// Package fixgenesis implements the fix-genesis command.
package fixgenesis

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	consensus "github.com/oasislabs/oasis-core/go/consensus/genesis"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	keymanager "github.com/oasislabs/oasis-core/go/keymanager/api"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

const cfgNewGenesis = "genesis.new_file"

var (
	fixGenesisCmd = &cobra.Command{
		Use:   "fix-genesis",
		Short: "fix a genesis document",
		Run:   doFixGenesis,
	}

	newGenesisFlag = flag.NewFlagSet("", flag.ContinueOnError)

	logger = logging.GetLogger("cmd/debug/fix-genesis")
)

type oldDocument struct {
	// Height is the block height at which the document was generated.
	Height int64 `json:"height"`
	// Time is the time the genesis block was constructed.
	Time time.Time `json:"genesis_time"`
	// ChainID is the ID of the chain.
	ChainID string `json:"chain_id"`
	// EpochTime is the timekeeping genesis state.
	EpochTime epochtime.Genesis `json:"epochtime"`
	// Registry is the registry genesis state.
	Registry oldRegistry `json:"registry"`
	// RootHash is the roothash genesis state.
	RootHash roothash.Genesis `json:"roothash"`
	// Staking is the staking genesis state.
	Staking staking.Genesis `json:"staking"`
	// KeyManager is the key manager genesis state.
	KeyManager keymanager.Genesis `json:"keymanager"`
	// Scheduler is the scheduler genesis state.
	Scheduler scheduler.Genesis `json:"scheduler"`
	// Beacon is the beacon genesis state.
	Beacon beacon.Genesis `json:"beacon"`
	// Consensus is the consensus genesis state.
	Consensus consensus.Genesis `json:"consensus"`
	// HaltEpoch is the epoch height at which the network will stop processing
	// any transactions and will halt.
	HaltEpoch epochtime.EpochTime `json:"halt_epoch"`
	// Extra data is arbitrary extra data that is part of the
	// genesis block but is otherwise ignored by the protocol.
	ExtraData map[string][]byte `json:"extra_data"`
}

type oldRegistry struct {
	// Parameters are the registry consensus parameters.
	Parameters registry.ConsensusParameters `json:"params"`
	// Entities is the initial list of entities.
	Entities []*entity.SignedEntity `json:"entities,omitempty"`
	// Runtimes is the initial list of runtimes.
	Runtimes []*registry.SignedRuntime `json:"runtimes,omitempty"`
	// SuspendedRuntimes is the list of suspended runtimes.
	SuspendedRuntimes []*registry.SignedRuntime `json:"suspended_runtimes,omitempty"`
	// Nodes is the initial list of nodes.
	Nodes []*oldSignedNode `json:"nodes,omitempty"`
	// NodeStatuses is a set of node statuses.
	NodeStatuses map[signature.PublicKey]*registry.NodeStatus `json:"node_statuses,omitempty"`
}

type oldSignedNode struct {
	signature.Signed
}

func doFixGenesis(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	// Load the old genesis document.
	f := flags.GenesisFile()
	raw, err := ioutil.ReadFile(f)
	if err != nil {
		logger.Error("failed to open genesis file",
			"err", err,
		)
		os.Exit(1)
	}

	// Parse as the old format.  At some point all the important things
	// will be versioned, but this is not that time.
	var oldDoc oldDocument
	if err = json.Unmarshal(raw, &oldDoc); err != nil {
		logger.Error("failed to parse old genesis file",
			"err", err,
		)
		os.Exit(1)
	}

	// Actually fix the genesis document.
	newDoc, err := updateGenesisDoc(&oldDoc)
	if err != nil {
		logger.Error("failed to fix genesis document",
			"err", err,
		)
		os.Exit(1)
	}

	// Validate the new genesis document.
	if err = newDoc.SanityCheck(); err != nil {
		logger.Error("new genesis document sanity check failed",
			"err", err,
		)
		os.Exit(1)
	}

	// Write out the new genesis document.
	w, shouldClose, err := cmdCommon.GetOutputWriter(cmd, cfgNewGenesis)
	if err != nil {
		logger.Error("failed to get writer for fixed genesis file",
			"err", err,
		)
		os.Exit(1)
	}
	if shouldClose {
		defer w.Close()
	}
	if raw, err = json.Marshal(newDoc); err != nil {
		logger.Error("failed to marshal fixed genesis document into JSON",
			"err", err,
		)
		os.Exit(1)
	}
	if _, err = w.Write(raw); err != nil {
		logger.Error("failed to write new genesis file",
			"err", err,
		)
		os.Exit(1)
	}
}

func updateGenesisDoc(oldDoc *oldDocument) (*genesis.Document, error) {
	// Create the new genesis document template.
	newDoc := &genesis.Document{
		Height:     oldDoc.Height,
		Time:       oldDoc.Time,
		ChainID:    oldDoc.ChainID,
		EpochTime:  oldDoc.EpochTime,
		RootHash:   oldDoc.RootHash,
		Staking:    oldDoc.Staking,
		KeyManager: oldDoc.KeyManager,
		Scheduler:  oldDoc.Scheduler,
		Beacon:     oldDoc.Beacon,
		Consensus:  oldDoc.Consensus,
		HaltEpoch:  oldDoc.HaltEpoch,
		ExtraData:  oldDoc.ExtraData,
	}

	// This currently is entirely registry genesis state changes.
	oldReg, newReg := oldDoc.Registry, newDoc.Registry

	// First copy the registry things that have not changed.
	newReg.Parameters = oldReg.Parameters
	newReg.Entities = oldReg.Entities
	newReg.Runtimes = oldReg.Runtimes
	newReg.SuspendedRuntimes = oldReg.SuspendedRuntimes
	newReg.NodeStatuses = oldReg.NodeStatuses

	// The node descriptor signature envelope format in the registry has
	// changed.  Convert to the new envelope.
	//
	// Note: Actually using the genesis document requires that some
	// signature checks be disabled.
	for _, osn := range oldReg.Nodes {
		var nsn node.MultiSignedNode
		nsn.MultiSigned.Signatures = []signature.Signature{osn.Signed.Signature}

		// Since the last public release, the node role flags have
		// changed.  Rewrite all of the descriptors, since we only will
		// have validators, and signature validation at genesis is
		// disabled.
		var n node.Node
		if err := cbor.Unmarshal(osn.Signed.Blob, &n); err != nil {
			return nil, fmt.Errorf("updateGenesisDoc: failed to unmarshal node: %w", err)
		}
		n.Roles = node.RoleValidator
		nsn.MultiSigned.Blob = cbor.Marshal(&n)

		newReg.Nodes = append(newReg.Nodes, &nsn)
	}

	return newDoc, nil
}

// Register registers the fix-genesis sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	fixGenesisCmd.PersistentFlags().AddFlagSet(flags.GenesisFileFlags)
	fixGenesisCmd.PersistentFlags().AddFlagSet(newGenesisFlag)
	parentCmd.AddCommand(fixGenesisCmd)
}

func init() {
	newGenesisFlag.String(cfgNewGenesis, "genesis_fixed.json", "path to fixed genesis document")
	_ = viper.BindPFlags(newGenesisFlag)
}
