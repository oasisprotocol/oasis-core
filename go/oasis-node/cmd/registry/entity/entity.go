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

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	signerFile "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	cmdContext "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/context"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

const (
	CfgNodeID         = "entity.node.id"
	CfgNodeDescriptor = "entity.node.descriptor"
	CfgReuseSigner    = "entity.reuse_signer"

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

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, registry.Backend) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := registry.NewRegistryClient(conn)
	return conn, client
}

func doInit(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir, err := cmdSigner.CLIDirOrPwd()
	if err != nil {
		logger.Error("failed to query data directory",
			"err", err,
		)
		os.Exit(1)
	}

	switch cmdSigner.Backend() {
	case signerFile.SignerName:
		// Loosely check to see if there is an existing entity.  This isn't perfect, just "oopsie"
		// avoidance.
		if _, _, err = loadOrGenerateEntity(dataDir, false); err == nil {
			switch cmdFlags.Force() {
			case true:
				logger.Warn("overwriting existing entity")
			default:
				logger.Error("existing entity exists, specify --force to overwrite")
				os.Exit(1)
			}
		}
	default:
		// For any other signers, skip the check as creating the factory twice may be a bad idea in
		// case where the first instance gets exclusive access to a resource (e.g., an HSM).
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

	dataDir, err := cmdSigner.CLIDirOrPwd()
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
	ent.Nodes = nil
	for _, v := range viper.GetStringSlice(CfgNodeID) {
		var nodeID signature.PublicKey
		if err = nodeID.UnmarshalText([]byte(v)); err != nil {
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

		var signedNode node.MultiSignedNode
		if err = json.Unmarshal(b, &signedNode); err != nil {
			logger.Error("failed to parse signed node descriptor",
				"err", err,
			)
			os.Exit(1)
		}
		if len(signedNode.Signatures) == 0 {
			logger.Error("node genesis descriptor is missing signatures")
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
		if !signedNode.Signatures[0].PublicKey.Equal(n.ID) {
			logger.Error("node genesis descriptor is not self signed",
				"signer", signedNode.Signatures[0].PublicKey,
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
	prettySigned, err := cmdCommon.PrettyJSONMarshal(signed)
	if err != nil {
		logger.Error("failed to get pretty JSON of signed entity genesis registration",
			"err", err,
		)
		os.Exit(1)
	}
	if err = ioutil.WriteFile(filepath.Join(dataDir, entityGenesisFilename), prettySigned, 0o600); err != nil {
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

	genesis := cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	ent, signer, err := cmdCommon.LoadEntitySigner()
	if err != nil {
		logger.Error("failed to load entity and its signer",
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

	cmdConsensus.SignAndSaveTx(cmdContext.GetCtxWithGenesisInfo(genesis), tx, signer)
}

func doGenDeregister(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	genesis := cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := registry.NewDeregisterEntityTx(nonce, fee)

	cmdConsensus.SignAndSaveTx(cmdContext.GetCtxWithGenesisInfo(genesis), tx, nil)
}

func doList(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	entities, err := client.GetEntities(context.Background(), consensus.HeightLatest)
	if err != nil {
		logger.Error("failed to query entities",
			"err", err,
		)
		os.Exit(1)
	}

	for _, ent := range entities {
		var entString string
		switch cmdFlags.Verbose() {
		case true:
			prettyEnt, err := cmdCommon.PrettyJSONMarshal(ent)
			if err != nil {
				logger.Error("failed to get pretty JSON of entity",
					"err", err,
					"entity ID", ent.ID.String(),
				)
				entString = fmt.Sprintf("[invalid pretty JSON for entity %s]", ent.ID)
			} else {
				entString = string(prettyEnt)
			}
		default:
			entString = ent.ID.String()
		}

		fmt.Println(entString)
	}
}

func loadOrGenerateEntity(dataDir string, generate bool) (*entity.Entity, signature.Signer, error) {
	if cmdFlags.DebugTestEntity() {
		return entity.TestEntity()
	}

	entityDir, err := cmdSigner.CLIDirOrPwd()
	if err != nil {
		logger.Error("failed to retrieve entity dir",
			"err", err,
		)
		os.Exit(1)
	}
	entitySignerFactory, err := cmdSigner.NewFactory(cmdSigner.Backend(), entityDir, signature.SignerEntity)
	if err != nil {
		return nil, nil, fmt.Errorf("loadOrGenerateEntity: failed to create signer factory: %w", err)
	}

	if generate {
		template := &entity.Entity{
			Versioned: cbor.NewVersioned(entity.LatestDescriptorVersion),
		}

		if viper.GetBool(CfgReuseSigner) {
			signer, err := entitySignerFactory.Load(signature.SignerEntity)
			if err != nil {
				return nil, nil, fmt.Errorf("loadOrGenerateEntity: failed to load existing signer: %w", err)
			}
			ent, err := entity.GenerateWithSigner(dataDir, signer, template)
			return ent, signer, err
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
	entityFlags.AddFlagSet(cmdSigner.Flags)
	entityFlags.AddFlagSet(cmdSigner.CLIFlags)
	_ = viper.BindPFlags(entityFlags)

	initFlags.Bool(CfgReuseSigner, false, "Reuse entity signer instead of generating a new one")
	initFlags.AddFlagSet(cmdFlags.ForceFlags)
	initFlags.AddFlagSet(cmdFlags.DebugTestEntityFlags)
	initFlags.AddFlagSet(cmdFlags.DebugDontBlameOasisFlag)
	initFlags.AddFlagSet(entityFlags)
	_ = viper.BindPFlags(initFlags)

	updateFlags.StringSlice(CfgNodeID, nil, "ID(s) of nodes associated with this entity")
	updateFlags.StringSlice(CfgNodeDescriptor, nil, "Node genesis descriptor(s) of nodes associated with this entity")
	_ = viper.BindPFlags(updateFlags)
	updateFlags.AddFlagSet(cmdFlags.DebugTestEntityFlags)
	updateFlags.AddFlagSet(cmdFlags.DebugDontBlameOasisFlag)
	updateFlags.AddFlagSet(entityFlags)

	registerOrDeregisterFlags.AddFlagSet(cmdFlags.DebugTestEntityFlags)
	registerOrDeregisterFlags.AddFlagSet(cmdConsensus.TxFlags)
	registerOrDeregisterFlags.AddFlagSet(cmdFlags.AssumeYesFlag)
}
