// Package genesis implements the genesis sub-commands.
package genesis

import (
	"context"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	genesis "github.com/oasislabs/ekiden/go/genesis/api"
	genesisGrpc "github.com/oasislabs/ekiden/go/grpc/genesis"
	keymanager "github.com/oasislabs/ekiden/go/keymanager/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	staking "github.com/oasislabs/ekiden/go/staking/api"
)

const (
	cfgEntity             = "entity"
	cfgRuntime            = "runtime"
	cfgNode               = "node"
	cfgRootHash           = "roothash"
	cfgKeyManager         = "keymanager"
	cfgKeyManagerOperator = "keymanager.operator"
	cfgStaking            = "staking"
	cfgBlockHeight        = "height"

	// Our 'entity' flag overlaps with the common flag 'entity'.
	// We bind it to a separate Viper key to disambiguate at runtime.
	viperEntity = "provision_entity"
)

var (
	dumpGenesisFlags = flag.NewFlagSet("", flag.ContinueOnError)
	initGenesisFlags = flag.NewFlagSet("", flag.ContinueOnError)

	genesisCmd = &cobra.Command{
		Use:   "genesis",
		Short: "genesis block utilities",
	}

	initGenesisCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize the genesis file",
		Run:   doInitGenesis,
	}

	dumpGenesisCmd = &cobra.Command{
		Use:   "dump",
		Short: "dump state into genesis file",
		Run:   doDumpGenesis,
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

	f := flags.GenesisFile()
	if len(f) == 0 {
		logger.Error("failed to determine output location")
		return
	}

	// Build the genesis state, if any.
	doc := &genesis.Document{
		Time: time.Now(),
	}
	entities := viper.GetStringSlice(viperEntity)
	runtimes := viper.GetStringSlice(cfgRuntime)
	nodes := viper.GetStringSlice(cfgNode)
	if err := AppendRegistryState(doc, entities, runtimes, nodes, logger); err != nil {
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
func AppendRegistryState(doc *genesis.Document, entities, runtimes, nodes []string, l *logging.Logger) error {
	regSt := registry.Genesis{
		Entities: make([]*entity.SignedEntity, 0, len(entities)),
		Runtimes: make([]*registry.SignedRuntime, 0, len(runtimes)),
		Nodes:    make([]*node.SignedNode, 0, len(nodes)),
	}

	entMap := make(map[signature.MapKey]bool)
	appendToEntities := func(signedEntity *entity.SignedEntity, ent *entity.Entity) error {
		idKey := ent.ID.ToMapKey()
		if entMap[idKey] {
			return errors.New("genesis: duplicate entity registration")
		}
		entMap[idKey] = true

		regSt.Entities = append(regSt.Entities, signedEntity)

		return nil
	}

	loadSignedEntity := func(fn string) (*entity.SignedEntity, *entity.Entity, error) {
		b, err := ioutil.ReadFile(fn)
		if err != nil {
			return nil, nil, err
		}

		var signedEntity entity.SignedEntity
		if err = json.Unmarshal(b, &signedEntity); err != nil {
			return nil, nil, err
		}

		var ent entity.Entity
		if err := signedEntity.Open(registry.RegisterGenesisEntitySignatureContext, &ent); err != nil {
			return nil, nil, err
		}

		return &signedEntity, &ent, nil
	}

	for _, v := range entities {
		signedEntity, ent, err := loadSignedEntity(v)
		if err != nil {
			l.Error("failed to load genesis entity",
				"err", err,
				"filename", v,
			)
			return err
		}

		if err = appendToEntities(signedEntity, ent); err != nil {
			l.Error("failed to process genesis entity",
				"err", err,
				"filename", v,
			)
		}
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

		signedEntity, err := entity.SignEntity(signer, registry.RegisterGenesisEntitySignatureContext, ent)
		if err != nil {
			l.Error("failed to sign test entity",
				"err", err,
			)
			return err
		}

		if err = appendToEntities(signedEntity, ent); err != nil {
			l.Error("failed to process test entity",
				"err", err,
			)
			return err
		}

		regSt.KeyManagerOperator = ent.ID
	}

	if s := viper.GetString(cfgKeyManagerOperator); s != "" {
		_, ent, err := loadSignedEntity(s)
		if err != nil {
			l.Error("failed to load key manager operator entity",
				"err", err,
				"filename", s,
			)
			return err
		}

		if !entMap[ent.ID.ToMapKey()] {
			l.Error("key manager operator is not a genesis entity",
				"id", ent.ID,
			)
			return registry.ErrNoSuchEntity
		}

		regSt.KeyManagerOperator = ent.ID
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

	for _, v := range nodes {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			l.Error("failed to load genesis node registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		var n node.SignedNode
		if err = json.Unmarshal(b, &n); err != nil {
			l.Error("failed to parse genesis node registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		regSt.Nodes = append(regSt.Nodes, &n)
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

func doDumpGenesis(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	if err := common.Init(); err != nil {
		common.EarlyLogAndExit(err)
	}

	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}
	defer conn.Close()

	client := genesisGrpc.NewGenesisClient(conn)

	req := &genesisGrpc.GenesisRequest{
		Height: viper.GetInt64(cfgBlockHeight),
	}
	result, err := client.ToGenesis(ctx, req)
	if err != nil {
		logger.Error("failed to generate genesis document",
			"err", err,
		)
		os.Exit(1)
	}

	w, shouldClose, err := common.GetOutputWriter(cmd, flags.CfgGenesisFile)
	if err != nil {
		logger.Error("failed to get writer for genesis file",
			"err", err,
		)
		os.Exit(1)
	}
	if shouldClose {
		defer w.Close()
	}

	if _, err = w.Write(result.Json); err != nil {
		logger.Error("failed to write genesis file",
			"err", err,
		)
		os.Exit(1)
	}
}

// Register registers the genesis sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	initGenesisCmd.Flags().AddFlagSet(initGenesisFlags)
	dumpGenesisCmd.Flags().AddFlagSet(dumpGenesisFlags)
	dumpGenesisCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)

	for _, v := range []*cobra.Command{
		initGenesisCmd,
		dumpGenesisCmd,
	} {
		genesisCmd.AddCommand(v)
	}

	parentCmd.AddCommand(genesisCmd)
}

func init() {
	dumpGenesisFlags.Int64(cfgBlockHeight, 0, "block height at which to dump state")
	_ = viper.BindPFlags(dumpGenesisFlags)
	dumpGenesisFlags.AddFlagSet(flags.GenesisFileFlags)

	initGenesisFlags.StringSlice(cfgRuntime, nil, "path to runtime registration file")
	initGenesisFlags.StringSlice(cfgNode, nil, "path to node registration file")
	initGenesisFlags.StringSlice(cfgRootHash, nil, "path to roothash genesis blocks file")
	initGenesisFlags.String(cfgStaking, "", "path to staking genesis file")
	initGenesisFlags.StringSlice(cfgKeyManager, nil, "path to key manager genesis status file")
	initGenesisFlags.String(cfgKeyManagerOperator, "", "path to key manager operator entity registration file")
	_ = viper.BindPFlags(initGenesisFlags)
	initGenesisFlags.StringSlice(cfgEntity, nil, "path to entity registration file")
	_ = viper.BindPFlag(viperEntity, initGenesisFlags.Lookup(cfgEntity))
	initGenesisFlags.AddFlagSet(flags.DebugTestEntityFlags)
	initGenesisFlags.AddFlagSet(flags.ConsensusBackendFlag)
	initGenesisFlags.AddFlagSet(flags.GenesisFileFlags)
}
