// Package entity implements the entity registry sub-commands.
package entity

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	grpcRegistry "github.com/oasislabs/ekiden/go/grpc/registry"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

const (
	cmdRegister = "register"

	cfgAllowEntitySignedNodes = "entity.debug.allow_entity_signed_nodes"
	cfgNodeID                 = "entity.node.id"
	cfgNodeDescriptor         = "entity.node.descriptor"

	entityGenesisFilename = "entity_genesis.json"
)

var (
	entityCmd = &cobra.Command{
		Use:   "entity",
		Short: "entity registry backend utilities",
	}

	initCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize an entity",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerInitFlags(cmd)
		},
		Run: doInit,
	}

	updateCmd = &cobra.Command{
		Use:   "update",
		Short: "update an entity",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerUpdateFlags(cmd)
		},
		Run: doUpdate,
	}

	registerCmd = &cobra.Command{
		Use:   cmdRegister,
		Short: "register an entity",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerRegisterOrDeregisterFlags(cmd)
		},
		Run: doRegisterOrDeregister,
	}

	deregisterCmd = &cobra.Command{
		Use:   "deregister",
		Short: "deregister an entity",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerRegisterOrDeregisterFlags(cmd)
		},
		Run: doRegisterOrDeregister,
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "list registered entities",
		PreRun: func(cmd *cobra.Command, args []string) {
			cmdGrpc.RegisterClientFlags(cmd, false)
			cmdFlags.RegisterVerbose(cmd)
		},
		Run: doList,
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

	dataDir, err := cmdCommon.DataDirOrPwd()
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

	dataDir, err := cmdCommon.DataDirOrPwd()
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
	ent.RegistrationTime = uint64(time.Now().Unix())
	ent.AllowEntitySignedNodes = viper.GetBool(cfgAllowEntitySignedNodes)

	ent.Nodes = nil
	for _, v := range viper.GetStringSlice(cfgNodeID) {
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
	for _, v := range viper.GetStringSlice(cfgNodeDescriptor) {
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
	nodeMap := make(map[signature.MapKey]bool)
	for _, v := range ent.Nodes {
		nodeMap[v.ToMapKey()] = true
	}
	ent.Nodes = make([]signature.PublicKey, 0, len(nodeMap))
	for k := range nodeMap {
		var nodeID signature.PublicKey
		nodeID.FromMapKey(k)
		ent.Nodes = append(ent.Nodes, nodeID)
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
	b := json.Marshal(signed)
	if err = ioutil.WriteFile(filepath.Join(dataDir, entityGenesisFilename), b, 0600); err != nil {
		logger.Error("failed to write signed entity genesis registration",
			"err", err,
		)
		return err
	}

	return nil
}

func doRegisterOrDeregister(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir, err := cmdCommon.DataDirOrPwd()
	if err != nil {
		logger.Error("failed to query data directory",
			"err", err,
		)
		os.Exit(1)
	}

	ent, privKey, err := loadOrGenerateEntity(dataDir, false)
	if err != nil {
		logger.Error("failed to load entity",
			"err", err,
		)
		os.Exit(1)
	}

	nrRetries := cmdFlags.Retries()
	for i := 0; i <= nrRetries; {
		if err = func() error {
			conn, client := doConnect(cmd)
			defer conn.Close()

			var actErr error
			switch cmd.Use == cmdRegister {
			case true:
				actErr = doRegister(client, ent, privKey)
			case false:
				actErr = doDeregister(client, ent, privKey)
			}
			return actErr
		}(); err == nil {
			return
		}

		if nrRetries > 0 {
			i++
		}
		if i <= nrRetries {
			time.Sleep(1 * time.Second)
		}
	}

	os.Exit(1)
}

func doRegister(client grpcRegistry.EntityRegistryClient, ent *entity.Entity, signer signature.Signer) error {
	ent.RegistrationTime = uint64(time.Now().Unix())
	signed, err := entity.SignEntity(signer, registry.RegisterEntitySignatureContext, ent)
	if err != nil {
		logger.Error("failed to sign entity",
			"err", err,
		)
		return err
	}

	req := &grpcRegistry.RegisterRequest{
		Entity: signed.ToProto(),
	}
	if _, err = client.RegisterEntity(context.Background(), req); err != nil {
		logger.Error("failed to register entity",
			"err", err,
		)
		return err
	}

	logger.Info("registered entity",
		"entity", signer.Public(),
	)

	return nil
}

func doDeregister(client grpcRegistry.EntityRegistryClient, ent *entity.Entity, signer signature.Signer) error {
	ts := registry.Timestamp(time.Now().Unix())
	signed, err := signature.SignSigned(signer, registry.DeregisterEntitySignatureContext, &ts)
	if err != nil {
		logger.Error("failed to sign deregistration",
			"err", err,
		)
		return err
	}

	req := &grpcRegistry.DeregisterRequest{
		Timestamp: signed.ToProto(),
	}
	if _, err = client.DeregisterEntity(context.Background(), req); err != nil {
		logger.Error("failed to deregister entity",
			"err", err,
		)
		return err
	}

	logger.Info("deregistered entity",
		"entity", signer.Public(),
	)

	return nil
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
			s = string(json.Marshal(&ent))
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

	// TODO/hsm: Configure factory dynamically.
	entitySignerFactory := fileSigner.NewFactory(dataDir, signature.SignerEntity)
	if generate {
		template := &entity.Entity{
			AllowEntitySignedNodes: viper.GetBool(cfgAllowEntitySignedNodes),
		}

		return entity.Generate(dataDir, entitySignerFactory, template)
	}

	return entity.Load(dataDir, entitySignerFactory)
}

func registerEntityFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgAllowEntitySignedNodes, false, "Entity signing key may be used for node registration (UNSAFE)")
	}

	for _, v := range []string{
		cfgAllowEntitySignedNodes,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

func registerInitFlags(cmd *cobra.Command) {
	cmdFlags.RegisterForce(cmd)
	cmdFlags.RegisterDebugTestEntity(cmd)

	registerEntityFlags(cmd)
}

func registerUpdateFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().StringSlice(cfgNodeID, nil, "ID(s) of nodes associated with this entity")
		cmd.Flags().StringSlice(cfgNodeDescriptor, nil, "Node genesis descriptor(s) of nodes associated with this entity")
	}

	for _, v := range []string{
		cfgNodeID,
		cfgNodeDescriptor,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}

	cmdFlags.RegisterDebugTestEntity(cmd)
	registerEntityFlags(cmd)
}

func registerRegisterOrDeregisterFlags(cmd *cobra.Command) {
	cmdFlags.RegisterRetries(cmd)
	cmdFlags.RegisterDebugTestEntity(cmd)
	cmdGrpc.RegisterClientFlags(cmd, false)
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

	registerInitFlags(initCmd)
	registerUpdateFlags(updateCmd)
	registerRegisterOrDeregisterFlags(registerCmd)
	registerRegisterOrDeregisterFlags(deregisterCmd)

	cmdFlags.RegisterVerbose(listCmd)
	cmdGrpc.RegisterClientFlags(listCmd, false)

	parentCmd.AddCommand(entityCmd)
}
