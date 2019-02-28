// Package tendermint implements the tendermint sub-commands.
package tendermint

import (
	"errors"
	"io/ioutil"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/tendermint/api"
	"github.com/oasislabs/ekiden/go/tendermint/bootstrap"
)

const (
	cfgGenesisFile = "genesis_file"
	cfgEntity      = "entity"
	cfgRuntime     = "runtime"
	cfgRootHash    = "roothash"
	cfgValidator   = "validator"
)

var (
	tendermintCmd = &cobra.Command{
		Use:   "tendermint",
		Short: "tendermint backend utilities",
	}

	initGenesisCmd = &cobra.Command{
		Use:   "init_genesis",
		Short: "initialize the genesis file",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerInitGenesisFlags(cmd)
		},
		Run: doInitGenesis,
	}

	logger = logging.GetLogger("cmd/tendermint")
)

func doInitGenesis(cmd *cobra.Command, args []string) {
	var ok bool
	defer func() {
		if !ok {
			os.Exit(1)
		}
	}()

	if err := common.Init(); err != nil {
		common.EarlyLogAndExit(err)
	}

	f := viper.GetString(cfgGenesisFile)
	if len(f) == 0 {
		logger.Error("failed to determine output location")
		return
	}

	validatorFiles := viper.GetStringSlice(cfgValidator)
	if len(validatorFiles) == 0 {
		logger.Error("at least one validator must be provided")
		return
	}

	validators := make([]*bootstrap.GenesisValidator, 0, len(validatorFiles))
	for _, v := range validatorFiles {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			logger.Error("failed to load genesis validator",
				"err", err,
				"filename", v,
			)
			return
		}

		var validator bootstrap.GenesisValidator
		if err := json.Unmarshal(b, &validator); err != nil {
			logger.Error("failed to parse genesis validator",
				"err", err,
				"filename", v,
			)
			return
		}
		validator.Power = 10 // TODO: Make this configurable.

		validators = append(validators, &validator)
	}

	// Build the genesis state, if any.
	st := &api.GenesisAppState{
		ABCIAppState: make(map[string][]byte),
	}
	entities := viper.GetStringSlice(cfgEntity)
	runtimes := viper.GetStringSlice(cfgRuntime)
	if err := AppendRegistryState(st, entities, runtimes, logger); err != nil {
		logger.Error("failed to parse registry genesis state",
			"err", err,
		)
		return
	}

	roothash := viper.GetStringSlice(cfgRootHash)
	if err := AppendRootHashState(st, roothash, logger); err != nil {
		logger.Error("failed to parse roothash genesis state",
			"err", err,
		)
		return
	}

	doc := &bootstrap.GenesisDocument{
		Validators:  validators,
		GenesisTime: time.Now(),
	}
	if len(st.ABCIAppState) > 0 {
		doc.AppState = string(json.Marshal(st))
	}

	b := json.Marshal(doc)
	if err := ioutil.WriteFile(f, b, 0600); err != nil {
		logger.Error("failed to save generated genesis document",
			"err", err,
		)
		return
	}

	ok = true
}

// AppendRegistryState appends the registry genesis state given a vector
// of entity registrations and runtime registrations.
func AppendRegistryState(st *api.GenesisAppState, entities, runtimes []string, l *logging.Logger) error {
	regSt := &api.GenesisRegistryState{
		Entities: make([]*entity.SignedEntity, 0, len(entities)),
		Runtimes: make([]*registry.SignedRuntime, 0, len(runtimes)),
	}

	for _, v := range entities {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			l.Error("failed to load genesis entity registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		var entity entity.SignedEntity
		if err = json.Unmarshal(b, &entity); err != nil {
			l.Error("failed to parse genesis entity registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		regSt.Entities = append(regSt.Entities, &entity)
	}

	for _, v := range runtimes {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			l.Error("failed to load genesis runtime registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		var rt registry.SignedRuntime
		if err = json.Unmarshal(b, &rt); err != nil {
			l.Error("failed to parse genesis runtime registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		regSt.Runtimes = append(regSt.Runtimes, &rt)
	}

	if len(regSt.Entities) > 0 || len(regSt.Runtimes) > 0 {
		st.ABCIAppState[api.RegistryAppName] = cbor.Marshal(regSt)
	}

	return nil
}

// AppendRootHashState appends the roothash genesis state given a vector
// of exported roothash blocks.
func AppendRootHashState(st *api.GenesisAppState, roothash []string, l *logging.Logger) error {
	rootSt := &api.GenesisRootHashState{
		Blocks: make(map[signature.MapKey]*block.Block),
	}

	for _, v := range roothash {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			l.Error("failed to load genesis roothash blocks",
				"err", err,
				"filename", v,
			)
			return err
		}

		var blocks []*block.Block
		if err = json.Unmarshal(b, &blocks); err != nil {
			l.Error("failed to parse genesis roothash blocks",
				"err", err,
				"filename", v,
			)
			return err
		}

		for _, blk := range blocks {
			var key signature.MapKey
			copy(key[:], blk.Header.Namespace[:])
			if _, ok := rootSt.Blocks[key]; ok {
				l.Error("duplicate genesis roothash block",
					"runtime_id", blk.Header.Namespace,
					"block", blk,
				)
				return errors.New("duplicate genesis roothash block")
			}
			rootSt.Blocks[key] = blk
		}
	}

	if len(rootSt.Blocks) > 0 {
		st.ABCIAppState[api.RootHashAppName] = cbor.Marshal(rootSt)
	}

	return nil
}

func registerInitGenesisFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgGenesisFile, "genesis.json", "path to created genesis document")
		cmd.Flags().StringSlice(cfgEntity, nil, "path to entity registration file")
		cmd.Flags().StringSlice(cfgRuntime, nil, "path to runtime registration file")
		cmd.Flags().StringSlice(cfgRootHash, nil, "path to roothash genesis blocks file")
		cmd.Flags().StringSlice(cfgValidator, nil, "path to validator file")
	}

	for _, v := range []string{
		cfgGenesisFile,
		cfgEntity,
		cfgRuntime,
		cfgRootHash,
		cfgValidator,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

// Register registers the tendermint sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	registerInitGenesisFlags(initGenesisCmd)
	initProvisionValidatorCmd(tendermintCmd)

	for _, v := range []*cobra.Command{
		initGenesisCmd,
	} {
		tendermintCmd.AddCommand(v)
	}

	parentCmd.AddCommand(tendermintCmd)
}
