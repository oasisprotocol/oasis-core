// Package node implements the node registry sub-commands.
package node

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/configparser"
)

const (
	CfgEntityID         = "node.entity_id"
	CfgExpiration       = "node.expiration"
	CfgTLSAddress       = "node.tls_address"
	CfgP2PAddress       = "node.p2p_address"
	CfgConsensusAddress = "node.consensus_address"
	CfgRole             = "node.role"
	CfgSelfSigned       = "node.is_self_signed"
	CfgNodeRuntimeID    = "node.runtime.id"

	optRoleComputeWorker = "compute-worker"
	optRoleKeyManager    = "key-manager"
	optRoleValidator     = "validator"

	NodeGenesisFilename = "node_genesis.json"

	maskCommitteeMember = node.RoleComputeWorker | node.RoleKeyManager
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

	isRegisteredCmd = &cobra.Command{
		Use:   "is-registered",
		Short: "check whether the node is registered",
		Run:   doIsRegistered,
	}

	logger = logging.GetLogger("cmd/registry/node")
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

func doInit(cmd *cobra.Command, args []string) { // nolint: gocyclo
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

	// Get the entity ID.
	var entityID signature.PublicKey

	idStr := viper.GetString(CfgEntityID)
	if idStr == "" {
		logger.Error("missing --node.entity_id command-line argument")
		os.Exit(1)
	}
	if err = entityID.UnmarshalText([]byte(idStr)); err != nil {
		logger.Error("malformed entity ID",
			"err", err,
		)
		os.Exit(1)
	}
	logger.Info("entity ID provided, assuming self-signed node registrations")

	// Provision the node identity.
	nodeSignerFactory, err := cmdSigner.NewFactory(
		cmdSigner.Backend(),
		dataDir,
		identity.RequiredSignerRoles...,
	)
	if err != nil {
		logger.Error("failed to initialize signer backend",
			"err", err,
		)
		os.Exit(1)
	}
	nodeIdentity, err := identity.LoadOrGenerate(dataDir, nodeSignerFactory, false)
	if err != nil {
		logger.Error("failed to load or generate node identity",
			"err", err,
		)
		os.Exit(1)
	}

	var nextPubKey signature.PublicKey
	if s := nodeIdentity.GetNextTLSSigner(); s != nil {
		nextPubKey = s.Public()
	}

	n := &node.Node{
		Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
		ID:         nodeIdentity.NodeSigner.Public(),
		EntityID:   entityID,
		Expiration: viper.GetUint64(CfgExpiration),
		TLS: node.TLSInfo{
			PubKey:     nodeIdentity.GetTLSSigner().Public(),
			NextPubKey: nextPubKey,
		},
		P2P: node.P2PInfo{
			ID: nodeIdentity.P2PSigner.Public(),
		},
		Consensus: node.ConsensusInfo{
			ID: nodeIdentity.ConsensusSigner.Public(),
		},
		VRF: &node.VRFInfo{
			ID: nodeIdentity.VRFSigner.Public(),
		},
		SoftwareVersion: version.SoftwareVersion,
	}
	if n.Roles, err = argsToRolesMask(); err != nil {
		logger.Error("failed to parse node roles mask",
			"err", err,
		)
		os.Exit(1)
	}

	runtimeIDs, err := configparser.GetRuntimes(viper.GetStringSlice(CfgNodeRuntimeID))
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

	for _, v := range viper.GetStringSlice(CfgTLSAddress) {
		var tlsAddr node.TLSAddress
		if tlsAddrErr := tlsAddr.UnmarshalText([]byte(v)); tlsAddrErr != nil {
			if addrErr := tlsAddr.Address.UnmarshalText([]byte(v)); addrErr != nil {
				logger.Error("failed to parse node's TLS address",
					"addrErr", addrErr,
					"tlsAddrErr", tlsAddrErr,
					"addr", v,
				)
				os.Exit(1)
			}
			tlsAddr.PubKey = n.TLS.PubKey
		}
		n.TLS.Addresses = append(n.TLS.Addresses, tlsAddr)
	}

	for _, v := range viper.GetStringSlice(CfgP2PAddress) {
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
	if n.HasRoles(maskCommitteeMember) && (len(n.TLS.Addresses) == 0 || len(n.P2P.Addresses) == 0) {
		logger.Error("nodes that are committee members require at least 1 TLS and 1 P2P address")
		os.Exit(1)
	}

	if n.HasRoles(node.RoleValidator) {
		consensusAddrs := viper.GetStringSlice(CfgConsensusAddress)
		if len(consensusAddrs) == 0 {
			logger.Error("validator nodes require a consensus address")
			os.Exit(1)
		}

		for _, v := range consensusAddrs {
			var consensusAddr node.ConsensusAddress
			if consensusErr := consensusAddr.UnmarshalText([]byte(v)); consensusErr != nil {
				if addrErr := consensusAddr.Address.UnmarshalText([]byte(v)); addrErr != nil {
					logger.Error("failed to parse node's consensus address",
						"addrErr", addrErr,
						"consensusErr", consensusErr,
						"addr", v,
					)
					os.Exit(1)
				}
				consensusAddr.ID = n.P2P.ID
			}
			n.Consensus.Addresses = append(n.Consensus.Addresses, consensusAddr)
		}
	}

	// Sign and write out the genesis node registration.
	signers := []signature.Signer{
		nodeIdentity.NodeSigner,
		nodeIdentity.P2PSigner,
		nodeIdentity.ConsensusSigner,
		nodeIdentity.VRFSigner,
		nodeIdentity.GetTLSSigner(),
	}

	signed, err := node.MultiSignNode(signers, registry.RegisterGenesisNodeSignatureContext, n)
	if err != nil {
		logger.Error("failed to sign node genesis registration",
			"err", err,
		)
		os.Exit(1)
	}
	prettySigned, err := cmdCommon.PrettyJSONMarshal(signed)
	if err != nil {
		logger.Error("failed to get pretty JSON of signed node genesis registration",
			"err", err,
		)
		os.Exit(1)
	}
	if err = ioutil.WriteFile(filepath.Join(dataDir, NodeGenesisFilename), prettySigned, 0o600); err != nil {
		logger.Error("failed to write signed node genesis registration",
			"err", err,
		)
		os.Exit(1)
	}
}

func argsToRolesMask() (node.RolesMask, error) {
	var rolesMask node.RolesMask
	for _, v := range viper.GetStringSlice(CfgRole) {
		v = strings.ToLower(v)
		switch v {
		case optRoleComputeWorker:
			rolesMask |= node.RoleComputeWorker
		case optRoleKeyManager:
			rolesMask |= node.RoleKeyManager
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

	nodes, err := client.GetNodes(context.Background(), consensus.HeightLatest)
	if err != nil {
		logger.Error("failed to query nodes",
			"err", err,
		)
		os.Exit(1)
	}

	for _, node := range nodes {
		var nodeString string
		switch cmdFlags.Verbose() {
		case true:
			prettyNode, err := cmdCommon.PrettyJSONMarshal(node)
			if err != nil {
				logger.Error("failed to get pretty JSON of node",
					"err", err,
					"node ID", node.ID.String(),
				)
				nodeString = fmt.Sprintf("[invalid pretty JSON for node %s]", node.ID)
			} else {
				nodeString = string(prettyNode)
			}
		default:
			nodeString = node.ID.String()
		}

		fmt.Println(nodeString)
	}
}

func doIsRegistered(cmd *cobra.Command, args []string) {
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

	// Load node's identity.
	nodeSignerFactory, err := fileSigner.NewFactory(dataDir, identity.RequiredSignerRoles...)
	if err != nil {
		logger.Error("failed to create node identity signer factory",
			"err", err,
		)
		os.Exit(1)
	}
	nodeIdentity, err := identity.Load(dataDir, nodeSignerFactory)
	if err != nil {
		logger.Error("failed to load node identity",
			"err", err,
		)
		os.Exit(1)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	nodes, err := client.GetNodes(context.Background(), consensus.HeightLatest)
	if err != nil {
		logger.Error("failed to query nodes",
			"err", err,
		)
		os.Exit(1)
	}

	for _, node := range nodes {
		if node.ID.Equal(nodeIdentity.NodeSigner.Public()) {
			fmt.Println("node is registered")
			os.Exit(0)
		}
	}
	fmt.Println("node is not registered")
	os.Exit(1)
}

// Register registers the node sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	initCmd.Flags().AddFlagSet(flags)
	initCmd.Flags().AddFlagSet(cmdFlags.DebugTestEntityFlags)
	initCmd.Flags().AddFlagSet(cmdSigner.Flags)
	initCmd.Flags().AddFlagSet(cmdSigner.CLIFlags)

	listCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)
	listCmd.Flags().AddFlagSet(cmdFlags.VerboseFlags)

	isRegisteredCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)

	for _, subCmd := range []*cobra.Command{
		initCmd,
		listCmd,
		isRegisteredCmd,
	} {
		nodeCmd.AddCommand(subCmd)
	}
	parentCmd.AddCommand(nodeCmd)
}

func init() {
	flags.String(CfgEntityID, "", "Entity ID that controls this node")
	flags.Uint64(CfgExpiration, 0, "Epoch that the node registration should expire")
	flags.StringSlice(CfgTLSAddress, nil, "Address(es) the node can be reached over TLS of the form [PubKey@]ip:port (where PubKey@ part is optional and represents base64 encoded node TLS public key)")
	flags.StringSlice(CfgP2PAddress, nil, "Address(es) the node can be reached over the P2P transport")
	flags.StringSlice(CfgConsensusAddress, nil, "Address(es) the node can be reached as a consensus member of the form [ID@]ip:port (where the ID@ part is optional and ID represents the node's public key)")
	flags.StringSlice(CfgRole, nil, "Role(s) of the node.  Supported values are \"compute-worker\", \"storage-worker\", \"transaction-scheduler\", \"key-manager\", \"merge-worker\", and \"validator\"")
	flags.Bool(CfgSelfSigned, true, "Node registration should be self-signed")
	flags.StringSlice(CfgNodeRuntimeID, nil, "Hex Encoded Runtime ID(s) of the node.")

	_ = viper.BindPFlags(flags)
}
