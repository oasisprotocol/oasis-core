// Package node implements the node registry sub-commands.
package node

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/identity"
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
	cfgEntityID         = "node.entity_id"
	cfgExpiration       = "node.expiration"
	cfgCommitteeAddress = "node.committee_address"
	cfgP2PAddress       = "node.p2p_address"
	cfgRole             = "node.role"

	optRoleComputeWorker        = "compute-worker"
	optRoleStorageWorker        = "storage-worker"
	optRoleTransactionScheduler = "transaction-scheduler"
	optRoleKeyManager           = "key-manager"
	optRoleMergeWorker          = "merge-worker"
	optRoleValidator            = "validator"

	nodeGenesisFilename = "node_genesis.json"

	maskCommitteeMember = node.RoleComputeWorker | node.RoleStorageWorker | node.RoleTransactionScheduler | node.RoleKeyManager | node.RoleMergeWorker
)

var (
	nodeCmd = &cobra.Command{
		Use:   "node",
		Short: "node registry backend utilities",
	}

	initCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize a node",
		PreRun: func(cmd *cobra.Command, args []string) {
			cmdFlags.RegisterDebugTestEntity(cmd)
			cmdFlags.RegisterEntity(cmd)
			registerNodeFlags(cmd)
		},
		Run: doInit,
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "list registered nodes",
		PreRun: func(cmd *cobra.Command, args []string) {
			cmdGrpc.RegisterClientFlags(cmd, false)
			cmdFlags.RegisterVerbose(cmd)
		},
		Run: doList,
	}

	logger = logging.GetLogger("cmd/registry/node")
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

	// Get the entity ID or entity.
	var (
		entityID signature.PublicKey

		entity *entity.Entity
		signer signature.Signer

		isSelfSigned bool
	)
	if idStr := viper.GetString(cfgEntityID); idStr != "" {
		if err = entityID.UnmarshalHex(idStr); err != nil {
			logger.Error("malformed entity ID",
				"err", err,
			)
			os.Exit(1)
		}
		logger.Info("entity ID provided, assuming self-signed node registrations")

		isSelfSigned = true
	} else {
		entity, signer, err = cmdCommon.LoadEntity(cmdFlags.Entity())
		if err != nil {
			logger.Error("failed to load entity",
				"err", err,
			)
			os.Exit(1)
		}

		entityID = entity.ID
		isSelfSigned = !entity.AllowEntitySignedNodes
		defer signer.Reset()
	}

	// Provision the node identity.
	nodeSignerFactory := fileSigner.NewFactory(dataDir, signature.SignerNode, signature.SignerP2P)
	nodeIdentity, err := identity.LoadOrGenerate(dataDir, nodeSignerFactory)
	if err != nil {
		logger.Error("failed to load or generate node identity",
			"err", err,
		)
		os.Exit(1)
	}

	if isSelfSigned {
		signer, err = nodeSignerFactory.Load(signature.SignerNode)
		if err != nil {
			// Should never happen.
			logger.Error("failed to load the node signing key",
				"err", err,
			)
			os.Exit(1)
		}
	}

	n := &node.Node{
		ID:         nodeIdentity.NodeSigner.Public(),
		EntityID:   entityID,
		Expiration: viper.GetUint64(cfgExpiration),
		Committee: node.CommitteeInfo{
			Certificate: nodeIdentity.TLSCertificate.Certificate[0],
		},
		P2P: node.P2PInfo{
			ID: nodeIdentity.P2PSigner.Public(),
		},
		RegistrationTime: uint64(time.Now().Unix()),
	}
	if n.Roles, err = argsToRolesMask(); err != nil {
		logger.Error("failed to parse node roles mask",
			"err", err,
		)
		os.Exit(1)
	}

	for _, v := range viper.GetStringSlice(cfgCommitteeAddress) {
		var addr node.Address
		if err = addr.UnmarshalText([]byte(v)); err != nil {
			logger.Error("failed to parse node committee address",
				"err", err,
				"addr", v,
			)
			os.Exit(1)
		}
		n.Committee.Addresses = append(n.Committee.Addresses, addr)
	}
	for _, v := range viper.GetStringSlice(cfgP2PAddress) {
		var addr node.Address
		if err = addr.UnmarshalText([]byte(v)); err != nil {
			logger.Error("failed to parse node P2P address",
				"err", err,
				"addr", v,
			)
			os.Exit(1)
		}
		n.P2P.Addresses = append(n.P2P.Addresses, addr)
	}
	if n.HasRoles(maskCommitteeMember) && (len(n.Committee.Addresses) == 0 || len(n.P2P.Addresses) == 0) {
		logger.Error("nodes that are commitee members require at least 1 committee and 1 P2P address")
		os.Exit(1)
	}

	// TODO: Once node.Node has `Consensus` field, populate it.
	if n.HasRoles(node.RoleValidator) {
		logger.Error("validator provisioning not supported yet")
		os.Exit(1)
	}

	// Sign and write out the genesis node registration.
	signed, err := node.SignNode(signer, registry.RegisterGenesisNodeSignatureContext, n)
	if err != nil {
		logger.Error("failed to sign node genesis registration",
			"err", err,
		)
		os.Exit(1)
	}
	b := json.Marshal(signed)
	if err = ioutil.WriteFile(filepath.Join(dataDir, nodeGenesisFilename), b, 0600); err != nil {
		logger.Error("failed to write signed node genesis registration",
			"err", err,
		)
		os.Exit(1)
	}
}

func argsToRolesMask() (node.RolesMask, error) {
	var rolesMask node.RolesMask
	for _, v := range viper.GetStringSlice(cfgRole) {
		v = strings.ToLower(v)
		switch v {
		case optRoleComputeWorker:
			rolesMask |= node.RoleComputeWorker
		case optRoleStorageWorker:
			rolesMask |= node.RoleStorageWorker
		case optRoleTransactionScheduler:
			rolesMask |= node.RoleTransactionScheduler
		case optRoleKeyManager:
			rolesMask |= node.RoleKeyManager
		case optRoleMergeWorker:
			rolesMask |= node.RoleMergeWorker
		case optRoleValidator:
			rolesMask |= node.RoleValidator
		default:
			return 0, fmt.Errorf("node: unsupported role: '%v'", v)
		}
	}
	return rolesMask, nil
}

func doList(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	nodes, err := client.GetNodes(context.Background(), &grpcRegistry.NodesRequest{})
	if err != nil {
		logger.Error("failed to query nodes",
			"err", err,
		)
		os.Exit(1)
	}

	for _, v := range nodes.GetNode() {
		var node node.Node
		if err = node.FromProto(v); err != nil {
			logger.Error("failed to de-serialize node",
				"err", err,
				"pb", v,
			)
			continue
		}

		var s string
		switch cmdFlags.Verbose() {
		case true:
			s = string(json.Marshal(&node))
		default:
			s = node.ID.String()
		}

		fmt.Printf("%v\n", s)
	}
}

func registerNodeFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgEntityID, "", "Entity ID that controls this node")
		cmd.Flags().Uint64(cfgExpiration, 0, "Epoch that the node registration should expire")
		cmd.Flags().StringSlice(cfgCommitteeAddress, nil, "Address(es) the node can be reached as a committee member")
		cmd.Flags().StringSlice(cfgP2PAddress, nil, "Address(es) the node node can be reached over the P2P transport")
		cmd.Flags().StringSlice(cfgRole, nil, "Role(s) of the node.  Supported values are \"compute-worker\", \"storage-worker\", \"transaction-worker\", \"key-manager\", \"merge-worker\", and \"validator\"")
	}

	for _, v := range []string{
		cfgEntityID,
		cfgExpiration,
		cfgCommitteeAddress,
		cfgP2PAddress,
		cfgRole,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

// Register registers the node sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	for _, v := range []*cobra.Command{
		initCmd,
		listCmd,
	} {
		nodeCmd.AddCommand(v)
	}

	cmdFlags.RegisterVerbose(listCmd)

	for _, v := range []*cobra.Command{
		initCmd,
	} {
		cmdFlags.RegisterDebugTestEntity(v)
		cmdFlags.RegisterEntity(v)
		registerNodeFlags(v)
	}

	for _, v := range []*cobra.Command{
		listCmd,
	} {
		cmdGrpc.RegisterClientFlags(v, false)
	}

	parentCmd.AddCommand(nodeCmd)
}
