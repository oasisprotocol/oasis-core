// Package entity implements the entity registry sub-commands.
package entity

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	grpcRegistry "github.com/oasislabs/oasis-core/go/grpc/registry"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/consensus"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

const (
	cfgAllowEntitySignedNodes = "entity.debug.allow_entity_signed_nodes"
	CfgNodeID                 = "entity.node.id"
	CfgNodeDescriptor         = "entity.node.descriptor"

	entityGenesisFilename = "entity_genesis.json"
)

var (
	entityFlags               = flag.NewFlagSet("", flag.ContinueOnError)
	initFlags                 = flag.NewFlagSet("", flag.ContinueOnError)
	updateFlags               = flag.NewFlagSet("", flag.ContinueOnError)
	registerOrDeregisterFlags = flag.NewFlagSet("", flag.ContinueOnError)

	entityCmd = &cobra.Command{
		Use:   "entity",
		Short: "entity registry backend utilities",
	}

	initCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize an entity",
		Run:   doInit,
	}

	updateCmd = &cobra.Command{
		Use:   "update",
		Short: "update an entity",
		Run:   doUpdate,
	}

	registerCmd = &cobra.Command{
		Use:   "gen_register",
		Short: "generate a register entity transaction",
		Run:   doGenRegister,
	}

	deregisterCmd = &cobra.Command{
		Use:   "gen_deregister",
		Short: "generate a deregister entity transaction",
		Run:   doGenDeregister,
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "list registered entities",
		Run:   doList,
	}

	logger = logging.GetLogger("cmd/registry/entity")
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, grpcRegistry.EntityRegistryClient) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := grpcRegistry.NewEntityRegistryClient(conn)

	return conn, client
}

func doInit(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir, err := cmdFlags.SignerDirOrPwd()
	if err != nil {
		logger.Error("failed to query data directory",
			"err", err,
		)
		os.Exit(1)
	}

	// Loosely check to see if there is an existing entity.  This isn't
	// perfect, just "oopsie" avoidance.
	if _, _, err = loadOrGenerateEntity(dataDir, false); err == nil {
		switch cmdFlags.Force() {
		case true:
			logger.Warn("overwriting existing entity")
		default:
			logger.Error("existing entity exists, specifiy --force to overwrite")
			os.Exit(1)
		}
	}

	// Generate a new entity.
	ent, signer, err := loadOrGenerateEntity(dataDir, true)
	if err != nil {
		logger.Error("failed to generate entity",
			"err", err,
		)
		os.Exit(1)
	}

	if err = signAndWriteEntityGenesis(dataDir, signer, ent); err != nil {
		os.Exit(1)
	}

	logger.Info("generated entity",
		"entity", ent.ID,
	)
}

func doUpdate(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir, err := cmdFlags.SignerDirOrPwd()
	if err != nil {
		logger.Error("failed to query data directory",
			"err", err,
		)
		os.Exit(1)
	}

	// Load the existing entity.
	ent, signer, err := loadOrGenerateEntity(dataDir, false)
	if err != nil {
		logger.Error("failed to load entity",
			"err", err,
		)
		os.Exit(1)
	}

	// Update the entity.
	ent.AllowEntitySignedNodes = viper.GetBool(cfgAllowEntitySignedNodes)

	ent.Nodes = nil
	for _, v := range viper.GetStringSlice(CfgNodeID) {
		var nodeID signature.PublicKey
		if err = nodeID.UnmarshalHex(v); err != nil {
			logger.Error("failed to parse node ID",
				"err", err,
				"node_id", v,
			)
			os.Exit(1)
		}
		ent.Nodes = append(ent.Nodes, nodeID)
	}
	for _, v := range viper.GetStringSlice(CfgNodeDescriptor) {
		var b []byte
		if b, err = ioutil.ReadFile(v); err != nil {
			logger.Error("failed to read node descriptor",
				"err", err,
				"path", v,
			)
			os.Exit(1)
		}

		var signedNode node.SignedNode
		if err = json.Unmarshal(b, &signedNode); err != nil {
			logger.Error("failed to parse signed node descriptor",
				"err", err,
			)
			os.Exit(1)
		}

		var n node.Node
		if err = signedNode.Open(registry.RegisterGenesisNodeSignatureContext, &n); err != nil {
			logger.Error("failed to validate signed node descriptor",
				"err", err,
			)
			os.Exit(1)
		}

		if !ent.ID.Equal(n.EntityID) {
			logger.Error("entity ID mismatch, node does not belong to this entity",
				"entity_id", ent.ID,
				"node_entity_id", n.EntityID,
			)
			os.Exit(1)
		}
		if !signedNode.Signature.PublicKey.Equal(n.ID) {
			logger.Error("node genesis descriptor is not self signed",
				"signer", signedNode.Signature.PublicKey,
			)
			os.Exit(1)
		}
		ent.Nodes = append(ent.Nodes, n.ID)
	}

	// De-duplicate the entity's nodes.
	nodeMap := make(map[signature.PublicKey]bool)
	for _, v := range ent.Nodes {
		nodeMap[v] = true
	}
	ent.Nodes = make([]signature.PublicKey, 0, len(nodeMap))
	for k := range nodeMap {
		ent.Nodes = append(ent.Nodes, k)
	}

	// Save the entity descriptor.
	if err = ent.Save(dataDir); err != nil {
		logger.Error("failed to persist entity descriptor",
			"err", err,
		)
		os.Exit(1)
	}

	// Regenerate the genesis document entity registration.
	if err = signAndWriteEntityGenesis(dataDir, signer, ent); err != nil {
		os.Exit(1)
	}

	logger.Info("updated entity",
		"entity", ent.ID,
	)
}

func signAndWriteEntityGenesis(dataDir string, signer signature.Signer, ent *entity.Entity) error {
	// Sign the entity registration for use in a genesis document.
	signed, err := entity.SignEntity(signer, registry.RegisterGenesisEntitySignatureContext, ent)
	if err != nil {
		logger.Error("failed to sign entity for genesis registration",
			"err", err,
		)
		return err
	}

	// Write out the signed entity registration.
	b, _ := json.Marshal(signed)
	if err = ioutil.WriteFile(filepath.Join(dataDir, entityGenesisFilename), b, 0600); err != nil {
		logger.Error("failed to write signed entity genesis registration",
			"err", err,
		)
		return err
	}

	return nil
}

func doGenRegister(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	entityDir, err := cmdFlags.SignerDirOrPwd()
	if err != nil {
		logger.Error("failed to retrieve entity dir",
			"err", err,
		)
		os.Exit(1)
	}

	ent, signer, err := cmdCommon.LoadEntity(cmdFlags.Signer(), entityDir)
	if err != nil {
		logger.Error("failed to load entity",
			"err", err,
		)
		os.Exit(1)
	}
	defer signer.Reset()

	signed, err := entity.SignEntity(signer, registry.RegisterEntitySignatureContext, ent)
	if err != nil {
		logger.Error("failed to sign entity descriptor",
			"err", err,
		)
		os.Exit(1)
	}

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := registry.NewRegisterEntityTx(nonce, fee, signed)

	cmdConsensus.SignAndSaveTx(tx)
}

func doGenDeregister(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := registry.NewDeregisterEntityTx(nonce, fee)

	cmdConsensus.SignAndSaveTx(tx)
}

func doList(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	entities, err := client.GetEntities(context.Background(), &grpcRegistry.EntitiesRequest{})
	if err != nil {
		logger.Error("failed to query entities",
			"err", err,
		)
		os.Exit(1)
	}

	for _, v := range entities.GetEntity() {
		var ent entity.Entity
		if err = ent.FromProto(v); err != nil {
			logger.Error("failed to de-serialize entity",
				"err", err,
				"pb", v,
			)
			continue
		}

		var s string
		switch cmdFlags.Verbose() {
		case true:
			b, _ := json.Marshal(&ent)
			s = string(b)
		default:
			s = ent.ID.String()
		}

		fmt.Printf("%v\n", s)
	}
}

func loadOrGenerateEntity(dataDir string, generate bool) (*entity.Entity, signature.Signer, error) {
	if cmdFlags.DebugTestEntity() {
		return entity.TestEntity()
	}

	if viper.GetBool(cfgAllowEntitySignedNodes) && !cmdFlags.DebugDontBlameOasis() {
		return nil, nil, fmt.Errorf("loadOrGenerateEntity: sanity check failed: one or more unsafe debug flags set")
	}

	entityDir, err := cmdFlags.SignerDirOrPwd()
	if err != nil {
		logger.Error("failed to retrieve entity dir",
			"err", err,
		)
		os.Exit(1)
	}
	entitySignerFactory, err := cmdCommon.SignerFactory(cmdFlags.Signer(), entityDir)
	if err != nil {
		return nil, nil, err
	}

	if generate {
		template := &entity.Entity{
			AllowEntitySignedNodes: viper.GetBool(cfgAllowEntitySignedNodes),
		}

		return entity.Generate(dataDir, entitySignerFactory, template)
	}

	return entity.Load(dataDir, entitySignerFactory)
}

// Register registers the entity sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	for _, v := range []*cobra.Command{
		initCmd,
		updateCmd,
		registerCmd,
		deregisterCmd,
		listCmd,
	} {
		entityCmd.AddCommand(v)
	}

	initCmd.Flags().AddFlagSet(initFlags)
	updateCmd.Flags().AddFlagSet(updateFlags)
	registerCmd.Flags().AddFlagSet(registerOrDeregisterFlags)
	deregisterCmd.Flags().AddFlagSet(registerOrDeregisterFlags)

	listCmd.Flags().AddFlagSet(cmdFlags.VerboseFlags)
	listCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)

	parentCmd.AddCommand(entityCmd)
}

func init() {
	entityFlags.Bool(cfgAllowEntitySignedNodes, false, "Entity signing key may be used for node registration (UNSAFE)")
	entityFlags.AddFlagSet(cmdFlags.SignerFlags)
	_ = entityFlags.MarkHidden(cfgAllowEntitySignedNodes)
	_ = viper.BindPFlags(entityFlags)

	initFlags.AddFlagSet(cmdFlags.ForceFlags)
	initFlags.AddFlagSet(cmdFlags.DebugTestEntityFlags)
	initFlags.AddFlagSet(cmdFlags.DebugDontBlameOasisFlag)
	initFlags.AddFlagSet(entityFlags)

	updateFlags.StringSlice(CfgNodeID, nil, "ID(s) of nodes associated with this entity")
	updateFlags.StringSlice(CfgNodeDescriptor, nil, "Node genesis descriptor(s) of nodes associated with this entity")
	_ = viper.BindPFlags(updateFlags)
	updateFlags.AddFlagSet(cmdFlags.DebugTestEntityFlags)
	updateFlags.AddFlagSet(cmdFlags.DebugDontBlameOasisFlag)
	updateFlags.AddFlagSet(entityFlags)

	registerOrDeregisterFlags.AddFlagSet(cmdFlags.DebugTestEntityFlags)
	registerOrDeregisterFlags.AddFlagSet(cmdConsensus.TxFlags)
}
