// Package node implements the node registry sub-commands.
package node

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	grpcRegistry "github.com/oasislabs/oasis-core/go/grpc/registry"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/worker/common/configparser"
)

const (
	cfgEntityID         = "node.entity_id"
	cfgExpiration       = "node.expiration"
	cfgCommitteeAddress = "node.committee_address"
	cfgP2PAddress       = "node.p2p_address"
	cfgConsensusAddress = "node.consensus_address"
	cfgRole             = "node.role"
	cfgSelfSigned       = "node.is_self_signed"
	cfgNodeRuntimeID    = "node.runtime.id"

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
	flags = flag.NewFlagSet("", flag.ContinueOnError)

	nodeCmd = &cobra.Command{
		Use:   "node",
		Short: "node registry backend utilities",
	}

	initCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize a node",
		Run:   doInit,
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "list registered nodes",
		Run:   doList,
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
		if viper.GetBool(cfgSelfSigned) {
			isSelfSigned = true
		}
		defer signer.Reset()
	}

	// Provision the node identity.
	nodeSignerFactory := fileSigner.NewFactory(dataDir, signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
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
		Consensus: node.ConsensusInfo{
			ID: nodeIdentity.ConsensusSigner.Public(),
		},
	}
	if n.Roles, err = argsToRolesMask(); err != nil {
		logger.Error("failed to parse node roles mask",
			"err", err,
		)
		os.Exit(1)
	}

	runtimeIDs, err := configparser.GetRuntimes(viper.GetStringSlice(cfgNodeRuntimeID))
	if err != nil {
		logger.Error("failed to parse node runtime id",
			"err", err,
		)
	}
	for _, r := range runtimeIDs {
		runtime := &node.Runtime{
			ID: r,
		}
		n.Runtimes = append(n.Runtimes, runtime)
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
		logger.Error("nodes that are committee members require at least 1 committee and 1 P2P address")
		os.Exit(1)
	}

	if n.HasRoles(node.RoleValidator) {
		consensusAddrs := viper.GetStringSlice(cfgConsensusAddress)
		if len(consensusAddrs) == 0 {
			logger.Error("validator nodes require a consensus address")
			os.Exit(1)
		}

		for _, v := range consensusAddrs {
			var consensusAddr node.ConsensusAddress
			if err = consensusAddr.UnmarshalText([]byte(v)); err != nil {
				if err = consensusAddr.Address.UnmarshalText([]byte(v)); err != nil {
					logger.Error("failed to parse node's consensus address",
						"err", err,
						"addr", v,
					)
					os.Exit(1)
				}
				consensusAddr.ID = n.ID
			}
			n.Consensus.Addresses = append(n.Consensus.Addresses, consensusAddr)
		}
	}

	// Sign and write out the genesis node registration.
	signed, err := node.SignNode(signer, registry.RegisterGenesisNodeSignatureContext, n)
	if err != nil {
		logger.Error("failed to sign node genesis registration",
			"err", err,
		)
		os.Exit(1)
	}
	b, _ := json.Marshal(signed)
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
			b, _ := json.Marshal(&node)
			s = string(b)
		default:
			s = node.ID.String()
		}

		fmt.Printf("%v\n", s)
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

	listCmd.Flags().AddFlagSet(cmdFlags.VerboseFlags)

	for _, v := range []*cobra.Command{
		initCmd,
	} {
		v.Flags().AddFlagSet(cmdFlags.DebugTestEntityFlags)
		v.Flags().AddFlagSet(cmdFlags.EntityFlags)
		v.Flags().AddFlagSet(flags)
	}

	for _, v := range []*cobra.Command{
		listCmd,
	} {
		v.Flags().AddFlagSet(cmdGrpc.ClientFlags)
	}

	parentCmd.AddCommand(nodeCmd)
}

func init() {
	flags.String(cfgEntityID, "", "Entity ID that controls this node")
	flags.Uint64(cfgExpiration, 0, "Epoch that the node registration should expire")
	flags.StringSlice(cfgCommitteeAddress, nil, "Address(es) the node can be reached as a committee member")
	flags.StringSlice(cfgP2PAddress, nil, "Address(es) the node can be reached over the P2P transport")
	flags.StringSlice(cfgConsensusAddress, nil, "Address(es) the node can be reached as a consensus member of the form [ID@]ip:port (where the ID@ part is optional and ID represents the node's public key)")
	flags.StringSlice(cfgRole, nil, "Role(s) of the node.  Supported values are \"compute-worker\", \"storage-worker\", \"transaction-scheduler\", \"key-manager\", \"merge-worker\", and \"validator\"")
	flags.Bool(cfgSelfSigned, false, "Node registration should be self-signed")
	flags.StringSlice(cfgNodeRuntimeID, nil, "Hex Encoded Runtime ID(s) of the node.")

	_ = viper.BindPFlags(flags)
}
