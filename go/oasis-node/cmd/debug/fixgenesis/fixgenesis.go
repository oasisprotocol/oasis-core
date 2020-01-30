// Package fixgenesis implements the fix-genesis command.
package fixgenesis

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common/logging"
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
	Registry registry.Genesis `json:"registry"`
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
		Registry:   oldDoc.Registry,
		RootHash:   oldDoc.RootHash,
		Staking:    oldDoc.Staking,
		KeyManager: oldDoc.KeyManager,
		Scheduler:  oldDoc.Scheduler,
		Beacon:     oldDoc.Beacon,
		Consensus:  oldDoc.Consensus,
		HaltEpoch:  oldDoc.HaltEpoch,
		ExtraData:  oldDoc.ExtraData,
	}

	// There is currently nothing to fix.

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
