// Package genesis implements the genesis sub-commands.
package genesis

import (
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	genesis "github.com/oasislabs/ekiden/go/genesis/api"
	keymanager "github.com/oasislabs/ekiden/go/keymanager/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	staking "github.com/oasislabs/ekiden/go/staking/api"
)

const (
	cfgGenesisFile = "genesis_file"
	cfgEntity      = "entity"
	cfgRuntime     = "runtime"
	cfgRootHash    = "roothash"
	cfgKeyManager  = "keymanager"
	cfgStaking     = "staking"
	cfgValidator   = "validator"
)

var (
	genesisCmd = &cobra.Command{
		Use:   "genesis",
		Short: "genesis block utilities",
	}

	initGenesisCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize the genesis file",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerInitGenesisFlags(cmd)
		},
		Run: doInitGenesis,
	}

	logger = logging.GetLogger("cmd/genesis")
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

	validators := make([]*genesis.SignedValidator, 0, len(validatorFiles))
	for _, v := range validatorFiles {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			logger.Error("failed to load genesis validator",
				"err", err,
				"filename", v,
			)
			return
		}

		var validator genesis.SignedValidator
		if err := json.Unmarshal(b, &validator); err != nil {
			logger.Error("failed to parse genesis validator",
				"err", err,
				"filename", v,
			)
			return
		}

		validators = append(validators, &validator)
	}

	// Build the genesis state, if any.
	doc := &genesis.Document{
		Time:       time.Now(),
		Validators: validators,
	}
	entities := viper.GetStringSlice(cfgEntity)
	runtimes := viper.GetStringSlice(cfgRuntime)
	if err := AppendRegistryState(doc, entities, runtimes, logger); err != nil {
		logger.Error("failed to parse registry genesis state",
			"err", err,
		)
		return
	}

	roothash := viper.GetStringSlice(cfgRootHash)
	if err := AppendRootHashState(doc, roothash, logger); err != nil {
		logger.Error("failed to parse roothash genesis state",
			"err", err,
		)
		return
	}

	keymanager := viper.GetStringSlice(cfgKeyManager)
	if err := AppendKeyManagerState(doc, keymanager, logger); err != nil {
		logger.Error("failed to parse key manager genesis state",
			"err", err,
		)
		return
	}

	staking := viper.GetString(cfgStaking)
	if err := AppendStakingState(doc, staking, logger); err != nil {
		logger.Error("failed to parse staking genesis state",
			"err", err,
		)
		return
	}

	// TODO: Ensure consistency/sanity.

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
func AppendRegistryState(doc *genesis.Document, entities, runtimes []string, l *logging.Logger) error {
	regSt := registry.Genesis{
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
	if flags.DebugTestEntity() {
		l.Warn("registering debug test entity")

		ent, signer, err := entity.TestEntity()
		if err != nil {
			l.Error("failed to retrive test entity",
				"err", err,
			)
			return err
		}

		signed, err := entity.SignEntity(signer, registry.RegisterGenesisEntitySignatureContext, ent)
		if err != nil {
			l.Error("failed to sign test entity",
				"err", err,
			)
			return err
		}

		if err = signed.Open(registry.RegisterGenesisEntitySignatureContext, ent); err != nil {
			l.Error("signed entity does not round trip",
				"err", err,
			)
			return err
		}

		regSt.Entities = append(regSt.Entities, signed)
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

	doc.Registry = regSt

	return nil
}

// AppendRootHashState appends the roothash genesis state given a vector
// of exported roothash blocks.
func AppendRootHashState(doc *genesis.Document, exports []string, l *logging.Logger) error {
	rootSt := roothash.Genesis{
		Blocks: make(map[signature.MapKey]*block.Block),
	}

	for _, v := range exports {
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

	doc.RootHash = rootSt

	return nil
}

// AppendKeyManagerState appends the key manager genesis state given a vector of
// key manager statuses.
func AppendKeyManagerState(doc *genesis.Document, statuses []string, l *logging.Logger) error {
	var kmSt keymanager.Genesis

	for _, v := range statuses {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			l.Error("failed to load genesis key manager status",
				"err", err,
				"filename", v,
			)
			return err
		}

		var status keymanager.Status
		if err = json.Unmarshal(b, &status); err != nil {
			l.Error("failed to parse genesis key manager status",
				"err", err,
				"filename", v,
			)
			return err
		}

		kmSt.Statuses = append(kmSt.Statuses, &status)
	}

	doc.KeyManager = kmSt

	return nil
}

// AppendStakingState appens the staking gensis state given a state file name.
func AppendStakingState(doc *genesis.Document, state string, l *logging.Logger) error {
	stakingSt := staking.Genesis{
		Ledger: make(map[signature.MapKey]*staking.GenesisLedgerEntry),
	}

	if state != "" {
		b, err := ioutil.ReadFile(state)
		if err != nil {
			l.Error("failed to load genesis staking status",
				"err", err,
				"filename", state,
			)
			return err
		}

		if err = json.Unmarshal(b, &stakingSt); err != nil {
			l.Error("failed to parse genesis staking status",
				"err", err,
				"filename", state,
			)
			return err
		}
	}
	if flags.DebugTestEntity() {
		l.Warn("granting stake to the debug test entity")

		ent, _, err := entity.TestEntity()
		if err != nil {
			l.Error("failed to retrive test entity",
				"err", err,
			)
			return err
		}

		// Ok then, we hold the world ransom for One Hundred Billion Dollars.
		var q staking.Quantity
		if err = q.FromBigInt(big.NewInt(100000000000)); err != nil {
			l.Error("failed to allocate test stake",
				"err", err,
			)
			return err
		}

		stakingSt.Ledger[ent.ID.ToMapKey()] = &staking.GenesisLedgerEntry{
			GeneralBalance: q,
			EscrowBalance:  q,
			Nonce:          0,
		}

		// Inflate the TotalSupply to account for the account's general and
		// escrow balances.
		_ = stakingSt.TotalSupply.Add(&q)
		_ = stakingSt.TotalSupply.Add(&q)
	}

	doc.Staking = stakingSt

	return nil
}

func registerInitGenesisFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgGenesisFile, "genesis.json", "path to created genesis document")
		cmd.Flags().StringSlice(cfgEntity, nil, "path to entity registration file")
		cmd.Flags().StringSlice(cfgRuntime, nil, "path to runtime registration file")
		cmd.Flags().StringSlice(cfgRootHash, nil, "path to roothash genesis blocks file")
		cmd.Flags().String(cfgStaking, "", "path to staking genesis file")
		cmd.Flags().StringSlice(cfgKeyManager, nil, "path to key manager genesis status file")
		cmd.Flags().StringSlice(cfgValidator, nil, "path to validator file")
	}

	for _, v := range []string{
		cfgGenesisFile,
		cfgEntity,
		cfgRuntime,
		cfgRootHash,
		cfgKeyManager,
		cfgStaking,
		cfgValidator,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}

	flags.RegisterDebugTestEntity(cmd)
	flags.RegisterConsensusBackend(cmd)
}

// Register registers the genesis sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	registerInitGenesisFlags(initGenesisCmd)
	initProvisionValidatorCmd(genesisCmd)

	for _, v := range []*cobra.Command{
		initGenesisCmd,
	} {
		genesisCmd.AddCommand(v)
	}

	parentCmd.AddCommand(genesisCmd)
}
