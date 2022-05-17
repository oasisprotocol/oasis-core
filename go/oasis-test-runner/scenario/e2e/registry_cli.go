package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
	cmdRegEnt "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/entity"
	cmdRegNode "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/node"
	cmdRegRuntime "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/runtime"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// RegistryCLI is the registry CLI test scenario.
var RegistryCLI scenario.Scenario = &registryCLIImpl{
	E2E: *NewE2E("registry-cli"),
}

type registryCLIImpl struct {
	E2E
}

func (sc *registryCLIImpl) Clone() scenario.Scenario {
	return &registryCLIImpl{
		E2E: sc.E2E.Clone(),
	}
}

func (sc *registryCLIImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.E2E.Fixture()
	if err != nil {
		return nil, err
	}

	// We will mock epochs for reclaiming the escrow.
	f.Network.SetMockEpoch()
	f.Network.SetInsecureBeacon()

	return f, nil
}

func (sc *registryCLIImpl) Run(childEnv *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	ctx := context.Background()
	sc.Logger.Info("waiting for nodes to register")
	if err := sc.Net.Controller().WaitNodesRegistered(ctx, 3); err != nil {
		return fmt.Errorf("waiting for nodes to register: %w", err)
	}
	sc.Logger.Info("nodes registered")

	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// Run the tests
	// registry entity and registry node subcommands
	if err := sc.testEntityAndNode(childEnv, cli); err != nil {
		return fmt.Errorf("error while running registry entity and node test: %w", err)
	}

	// registry runtime subcommands
	if err := sc.testRuntime(ctx, childEnv, cli); err != nil {
		return fmt.Errorf("error while running registry runtime test: %w", err)
	}

	// Stop the network.
	sc.Logger.Info("stopping the network")
	sc.Net.Stop()

	return nil
}

// testEntity tests registry entity subcommands.
func (sc *registryCLIImpl) testEntityAndNode(childEnv *env.Env, cli *cli.Helpers) error {
	// List entities.
	entities, err := sc.listEntities(childEnv)
	if err != nil {
		return err
	}
	// Two entities should be registered in our genesis block.
	if len(entities) != 2 {
		return fmt.Errorf("initial entity list wrong number of entities: %d, expected at least: %d. Entities: %s", len(entities), 2, entities)
	}

	// List nodes.
	nodes, err := sc.listNodes(childEnv)
	if err != nil {
		return err
	}
	// Three nodes should be registered in our genesis block initially.
	if len(nodes) != 3 {
		return fmt.Errorf("initial node list wrong number of nodes: %d, expected at least: %d. Nodes: %s", len(nodes), 3, nodes)
	}
	// Check that is-registered subcommand detects all validators as registered.
	for _, val := range sc.Net.Validators() {
		if err = sc.isRegistered(childEnv, val.Name, val.DataDir()); err != nil {
			return err
		}
	}

	// Init new entity.
	entDir, err := childEnv.NewSubDir("entity")
	if err != nil {
		return err
	}

	var ent *entity.Entity
	ent, err = sc.initEntity(childEnv, entDir.String())
	if err != nil {
		return err
	}

	// Init new node.
	nDir, err := childEnv.NewSubDir("node")
	if err != nil {
		return err
	}
	var n *node.Node
	n, err = sc.initNode(childEnv, ent, entDir.String(), nDir.String())
	if err != nil {
		return err
	}
	err = sc.isRegistered(childEnv, "node", nDir.String())
	if err == nil || !strings.Contains(err.Error(), "node is not registered") {
		return errors.New("is-registered should detect the new node is not registered")
	}

	// Update entity with a new node.
	var entUp *entity.Entity
	nodeGenesisFile := nDir.String() + "/node_genesis.json"
	entUp, err = sc.updateEntity(childEnv, []*node.Node{n}, []string{nodeGenesisFile}, entDir.String())
	if err != nil {
		return err
	}
	if entUp == nil {
		return fmt.Errorf("got empty entity after updating")
	}
	// Check whether the entity was updated.
	entBinary, _ := json.Marshal(ent)
	entUpBinary, _ := json.Marshal(entUp)
	if bytes.Equal(entBinary, entUpBinary) {
		return fmt.Errorf("update entity failed. Entity not changed: %s", string(entBinary))
	}
	if len(entUp.Nodes) != 1 {
		return fmt.Errorf("update entity failed. Wrong number of nodes: %d. Expected %d", len(entUp.Nodes), 1)
	}
	if !entUp.Nodes[0].Equal(n.ID) {
		return fmt.Errorf("update entity failed. Wrong node ID: %s. Expected %s", entUp.Nodes[0].String(), n.ID.String())
	}

	// Generate register entity transaction.
	registerTxPath := filepath.Join(childEnv.Dir(), "registry_entity_register.json")
	if err = sc.genRegisterEntityTx(childEnv, 0, registerTxPath, entDir.String()); err != nil {
		return err
	}

	// Submit register entity transaction.
	if err = cli.Consensus.SubmitTx(registerTxPath); err != nil {
		return fmt.Errorf("failed to submit entity register tx: %w", err)
	}

	// List entities.
	entities, err = sc.listEntities(childEnv)
	if err != nil {
		return err
	}
	// Three entities should now be registered after registration.
	if len(entities) != 3 {
		return fmt.Errorf("initial entity list wrong number of entities: %d, expected at least: %d. Entities: %s", len(entities), 3, entities)
	}

	// Generate deregister entity transaction.
	deregisterTxPath := filepath.Join(childEnv.Dir(), "registry_entity_deregister.json")
	if err = sc.genDeregisterEntityTx(childEnv, 1, deregisterTxPath, entDir.String()); err != nil {
		return err
	}

	// Submit deregister entity transaction.
	if err = cli.Consensus.SubmitTx(deregisterTxPath); err != nil {
		return fmt.Errorf("failed to submit entity deregister tx: %w", err)
	}

	// List entities.
	entities, err = sc.listEntities(childEnv)
	if err != nil {
		return err
	}
	// Only two entities should now be registered after deregistration.
	if len(entities) != 2 {
		return fmt.Errorf("initial entity list wrong number of entities: %d, expected at least: %d. Entities: %s", len(entities), 2, entities)
	}

	return nil
}

// listEntities lists currently registered entities.
func (sc *registryCLIImpl) listEntities(childEnv *env.Env) ([]signature.PublicKey, error) {
	sc.Logger.Info("listing all entities")
	args := []string{
		"registry", "entity", "list",
		"--" + grpc.CfgAddress, "unix:" + sc.Net.Validators()[0].SocketPath(),
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "list", sc.Net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("failed to list entities: error: %w output: %s", err, out.String())
	}
	entitiesStr := strings.Split(out.String(), "\n")

	var entities []signature.PublicKey
	for _, entStr := range entitiesStr {
		// Ignore last newline.
		if entStr == "" {
			continue
		}

		var ent signature.PublicKey
		if err = ent.UnmarshalText([]byte(entStr)); err != nil {
			return nil, fmt.Errorf("failed to parse entity ID (%s): error: %w output: %s", entStr, err, out.String())
		}
		entities = append(entities, ent)
	}

	return entities, nil
}

// loadEntity loads entity and signer from given directory.
func (sc *registryCLIImpl) loadEntity(entDir string) (*entity.Entity, error) {
	entitySignerFactory, err := fileSigner.NewFactory(entDir, signature.SignerEntity)
	if err != nil {
		return nil, fmt.Errorf("failed to create entity file signer: %w", err)
	}
	ent, _, err := entity.Load(entDir, entitySignerFactory)
	if err != nil {
		return nil, fmt.Errorf("failed to load entity: %w", err)
	}

	return ent, nil
}

// initEntity initializes new entity.
func (sc *registryCLIImpl) initEntity(childEnv *env.Env, entDir string) (*entity.Entity, error) {
	sc.Logger.Info("initializing new entity")

	args := []string{
		"registry", "entity", "init",
		"--" + cmdSigner.CfgSigner, fileSigner.SignerName,
		"--" + cmdSigner.CfgCLISignerDir, entDir,
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "entity-init", sc.Net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("failed to init entity: error: %w output: %s", err, out.String())
	}

	return sc.loadEntity(entDir)
}

// updateInit updates an entity.
func (sc *registryCLIImpl) updateEntity(childEnv *env.Env, nodes []*node.Node, nodeGenesisFiles []string, entDir string) (*entity.Entity, error) {
	sc.Logger.Info("update entity")

	var nodeIDs []string
	for _, n := range nodes {
		nodeIDs = append(nodeIDs, n.ID.String())
	}

	args := []string{
		"registry", "entity", "update",
		"--" + cmdSigner.CfgSigner, fileSigner.SignerName,
		"--" + cmdSigner.CfgCLISignerDir, entDir,
		"--" + cmdRegEnt.CfgNodeID, strings.Join(nodeIDs, ","),
		"--" + cmdRegEnt.CfgNodeDescriptor, strings.Join(nodeGenesisFiles, ","),
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "entity-update", sc.Net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("failed to update entity: error: %w output: %s", err, out.String())
	}

	return sc.loadEntity(entDir)
}

// listNodes lists currently registered nodes.
func (sc *registryCLIImpl) listNodes(childEnv *env.Env) ([]signature.PublicKey, error) {
	sc.Logger.Info("listing all nodes")
	args := []string{
		"registry", "node", "list",
		"--" + grpc.CfgAddress, "unix:" + sc.Net.Validators()[0].SocketPath(),
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "node-list", sc.Net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: error: %w output: %s", err, out.String())
	}
	nodesStr := strings.Split(out.String(), "\n")

	var nodes []signature.PublicKey
	for _, nodeStr := range nodesStr {
		// Ignore last newline.
		if nodeStr == "" {
			continue
		}

		var node signature.PublicKey
		if err = node.UnmarshalText([]byte(nodeStr)); err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

// isRegistered checks if the given node is registered.
func (sc *registryCLIImpl) isRegistered(childEnv *env.Env, nodeName, nodeDataDir string) error {
	sc.Logger.Info(fmt.Sprintf("checking if node %s is registered", nodeName))
	args := []string{
		"registry", "node", "is-registered",
		"--" + grpc.CfgAddress, "unix:" + sc.Net.Validators()[0].SocketPath(),
		"--" + cmdCommon.CfgDataDir, nodeDataDir,
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "is-registered", sc.Net.Config().NodeBinary, args)
	if err != nil {
		return fmt.Errorf("failed to check if node %s is registered: error: %w output: %s", nodeName, err, out.String())
	}
	return nil
}

// newTestNode returns a test node instance given the entityID.
func (sc *registryCLIImpl) newTestNode(entityID signature.PublicKey) (*node.Node, []string, []string, []string, error) {
	// Addresses.
	testAddresses := []node.Address{
		{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 12345,
			Zone: "",
		},
		{
			IP:   net.IPv4(127, 0, 0, 2),
			Port: 54321,
			Zone: "",
		},
	}
	testAddressesStr := []string{}
	for _, a := range testAddresses {
		testAddressesStr = append(testAddressesStr, a.String())
	}

	// Consensus addresses.
	testConsensusAddresses := []node.ConsensusAddress{
		{
			ID:      signature.PublicKey{},
			Address: testAddresses[0],
		},
		{
			ID:      signature.PublicKey{},
			Address: testAddresses[1],
		},
	}
	_ = testConsensusAddresses[0].ID.UnmarshalHex("1100000000000000000000000000000000000000000000000000000000000000")
	_ = testConsensusAddresses[1].ID.UnmarshalHex("1200000000000000000000000000000000000000000000000000000000000000")
	testConsensusAddressesStr := []string{}
	for _, a := range testConsensusAddresses {
		testConsensusAddressesStr = append(testConsensusAddressesStr, a.String())
	}

	// TLS addresses.
	testTLSAddresses := []node.TLSAddress{
		{
			PubKey:  signature.PublicKey{}, // Public key is generated afterwards.
			Address: testAddresses[0],
		},
		{
			PubKey:  signature.PublicKey{}, // PublicKey is generated afterwards.
			Address: testAddresses[1],
		},
	}
	testTLSAddressesStr := []string{}
	for _, a := range testTLSAddresses {
		testTLSAddressesStr = append(testTLSAddressesStr, a.String())
	}

	testNode := node.Node{
		Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
		ID:         signature.PublicKey{}, // ID is generated afterwards.
		EntityID:   entityID,
		Expiration: 42,
		TLS: node.TLSInfo{
			PubKey:    signature.PublicKey{}, // Public key is generated afterwards.
			Addresses: testTLSAddresses,
		},
		P2P: node.P2PInfo{
			ID:        signature.PublicKey{}, // ID is generated afterwards.
			Addresses: testAddresses,
		},
		Consensus: node.ConsensusInfo{
			ID:        signature.PublicKey{}, // ID is generated afterwards.
			Addresses: testConsensusAddresses,
		},
		Runtimes: []*node.Runtime{
			{
				ID: common.Namespace{}, // ID is set below.
			},
		},
		Roles:           node.RoleValidator,
		SoftwareVersion: version.SoftwareVersion,
	}
	_ = testNode.Runtimes[0].ID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")

	return &testNode, testAddressesStr, testConsensusAddressesStr, testTLSAddressesStr, nil
}

// initNode very "thoroughly" initializes new node and returns its instance.
func (sc *registryCLIImpl) initNode(childEnv *env.Env, ent *entity.Entity, entDir, dataDir string) (*node.Node, error) {
	sc.Logger.Info("initializing new node")

	// testNode will be our fixture for testing the CLI.
	testNode, testAddressesStr, testConsensusAddressesStr, testTLSAddressesStr, err := sc.newTestNode(ent.ID)
	if err != nil {
		return nil, err
	}

	// Helper for running the cmd and importing the generated node instance.
	runInitNode := func() (*node.Node, error) {
		args := []string{
			"registry", "node", "init",
			"--" + cmdRegNode.CfgTLSAddress, strings.Join(testTLSAddressesStr, ","),
			"--" + cmdRegNode.CfgConsensusAddress, strings.Join(testConsensusAddressesStr, ","),
			"--" + cmdRegNode.CfgEntityID, testNode.EntityID.String(),
			"--" + cmdRegNode.CfgExpiration, strconv.FormatUint(testNode.Expiration, 10),
			"--" + cmdRegNode.CfgSelfSigned, "1",
			"--" + cmdRegNode.CfgP2PAddress, strings.Join(testAddressesStr, ","),
			"--" + cmdRegNode.CfgRole, testNode.Roles.String(),
			"--" + cmdRegNode.CfgNodeRuntimeID, testNode.Runtimes[0].ID.String(),
			"--" + cmdSigner.CfgSigner, fileSigner.SignerName,
			"--" + cmdSigner.CfgCLISignerDir, entDir,
			"--" + cmdCommon.CfgDataDir, dataDir,
		}
		var out bytes.Buffer
		out, err = cli.RunSubCommandWithOutput(childEnv, sc.Logger, "init-node", sc.Net.Config().NodeBinary, args)
		if err != nil {
			return nil, fmt.Errorf("failed to init node: error: %w, output: %s", err, out.String())
		}

		// Check, if node genesis file was correctly written.
		var b []byte
		if b, err = ioutil.ReadFile(filepath.Join(dataDir, cmdRegNode.NodeGenesisFilename)); err != nil {
			return nil, fmt.Errorf("failed to open node genesis file: %w", err)
		}

		var signedNode node.MultiSignedNode
		if err = json.Unmarshal(b, &signedNode); err != nil {
			return nil, fmt.Errorf("failed to unmarshal signed node: %w", err)
		}

		var n node.Node
		if err = signedNode.Open(registry.RegisterGenesisNodeSignatureContext, &n); err != nil {
			return nil, fmt.Errorf("failed to validate signed node descriptor: %w", err)
		}

		return &n, nil
	}

	n, err := runInitNode()
	if err != nil {
		return nil, err
	}

	// Check the generated fields from imported node.
	if !n.ID.IsValid() {
		return nil, errors.New("new node ID is not valid")
	}
	if !n.TLS.PubKey.IsValid() {
		return nil, errors.New("new node TLS public key is not set")
	}
	if !n.P2P.ID.IsValid() {
		return nil, errors.New("new node P2P ID is not valid")
	}
	if !n.Consensus.ID.IsValid() {
		return nil, errors.New("new node Consensus ID is not valid")
	}

	// Replace our testNode fields with the generated one, so we can just marshal both nodes and compare the output afterwards.
	testNode.ID = n.ID
	testNode.TLS.PubKey = n.TLS.PubKey
	testNode.TLS.NextPubKey = n.TLS.NextPubKey
	testNode.P2P.ID = n.P2P.ID
	testNode.Consensus.ID = n.Consensus.ID
	testNode.VRF = n.VRF
	for idx := range testNode.TLS.Addresses {
		testNode.TLS.Addresses[idx].PubKey = n.TLS.PubKey
	}

	// Export both original and imported node to JSON and compare them.
	nStr, _ := json.Marshal(n)
	testNodeStr, _ := json.Marshal(testNode)
	if !bytes.Equal(nStr, testNodeStr) {
		return nil, fmt.Errorf("test node mismatch! Original node: %s, imported node: %s", testNodeStr, nStr)
	}

	// Now run node init again, this time by reading existing dataDir and expect the same node identity and JSON output.
	if err = os.Remove(filepath.Join(dataDir, cmdRegNode.NodeGenesisFilename)); err != nil {
		return nil, fmt.Errorf("error while removing test node genesis file: %w", err)
	}
	n, err = runInitNode()
	if err != nil {
		return nil, err
	}

	// TLS keys are regenerated each time, so replace them with new ones.
	testNode.TLS.PubKey = n.TLS.PubKey
	testNode.TLS.NextPubKey = n.TLS.NextPubKey
	for idx := range testNode.TLS.Addresses {
		testNode.TLS.Addresses[idx].PubKey = n.TLS.PubKey
	}
	testNodeStr, _ = json.Marshal(testNode)

	nStr, _ = json.Marshal(n)
	if !bytes.Equal(nStr, testNodeStr) {
		return nil, fmt.Errorf("second run test node mismatch! Original node: %s, imported node: %s", testNodeStr, nStr)
	}

	return n, nil
}

// genRegisterEntityTx calls registry entity gen_register.
func (sc *registryCLIImpl) genRegisterEntityTx(childEnv *env.Env, nonce int, txPath, entDir string) error {
	sc.Logger.Info("generating register entity tx")

	args := []string{
		"registry", "entity", "gen_register",
		"--" + consensus.CfgTxNonce, strconv.Itoa(nonce),
		"--" + consensus.CfgTxFile, txPath,
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(0),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + cmdCommon.CfgDebugAllowTestKeys,
		"--" + cmdSigner.CfgSigner, fileSigner.SignerName,
		"--" + cmdSigner.CfgCLISignerDir, entDir,
		"--" + flags.CfgGenesisFile, sc.Net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "gen_register", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("failed to generate register entity tx: error: %w output: %s", err, out.String())
	}

	return nil
}

// genDeregisterEntityTx calls registry entity gen_deregister.
func (sc *registryCLIImpl) genDeregisterEntityTx(childEnv *env.Env, nonce int, txPath, entDir string) error {
	sc.Logger.Info("generating deregister entity tx")

	args := []string{
		"registry", "entity", "gen_deregister",
		"--" + consensus.CfgTxNonce, strconv.Itoa(nonce),
		"--" + consensus.CfgTxFile, txPath,
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(0),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + cmdCommon.CfgDebugAllowTestKeys,
		"--" + cmdSigner.CfgSigner, fileSigner.SignerName,
		"--" + cmdSigner.CfgCLISignerDir, entDir,
		"--" + flags.CfgGenesisFile, sc.Net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "gen_deregister", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("failed to generate deregister entity tx: error: %w output: %s", err, out.String())
	}

	return nil
}

// testRuntime tests registry runtime subcommands.
func (sc *registryCLIImpl) testRuntime(ctx context.Context, childEnv *env.Env, cli *cli.Helpers) error {
	// List runtimes.
	runtimes, err := sc.listRuntimes(childEnv, false)
	if err != nil {
		return err
	}
	// No runtimes should be registered in our genesis block.
	if len(runtimes) != 0 {
		return fmt.Errorf("initial runtime list wrong number of runtimes: %d, expected: %d. Runtimes: %v", len(runtimes), 0, runtimes)
	}

	// Create runtime descriptor instance.
	testEntity, _, err := entity.TestEntity()
	if err != nil {
		return fmt.Errorf("TestEntity: %w", err)
	}
	var q quantity.Quantity
	_ = q.FromUint64(100)
	testRuntime := registry.Runtime{
		Versioned: cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		EntityID:  testEntity.ID,
		Kind:      registry.KindCompute,
		Executor: registry.ExecutorParameters{
			GroupSize:         1,
			GroupBackupSize:   2,
			AllowedStragglers: 1,
			RoundTimeout:      5,
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			BatchFlushTimeout: 11 * time.Second,
			MaxBatchSize:      12,
			MaxBatchSizeBytes: 1024,
			ProposerTimeout:   5,
		},
		AdmissionPolicy: registry.RuntimeAdmissionPolicy{
			EntityWhitelist: &registry.EntityWhitelistRuntimeAdmissionPolicy{
				Entities: map[signature.PublicKey]registry.EntityWhitelistConfig{
					testEntity.ID: {},
				},
			},
		},
		Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints{
			scheduler.KindComputeExecutor: {
				scheduler.RoleWorker: {
					MinPoolSize: &registry.MinPoolSizeConstraint{
						Limit: 1,
					},
					ValidatorSet: &registry.ValidatorSetConstraint{},
				},
				scheduler.RoleBackupWorker: {
					MinPoolSize: &registry.MinPoolSizeConstraint{
						Limit: 2,
					},
				},
			},
		},
		Staking: registry.RuntimeStakingParameters{
			Thresholds: map[staking.ThresholdKind]quantity.Quantity{
				staking.KindNodeCompute: q,
			},
		},
		GovernanceModel: registry.GovernanceEntity,
		Deployments: []*registry.VersionInfo{
			{
				ValidFrom: 1,
			},
		},
	}
	// Runtime ID 0x0 is for simple-keyvalue, 0xf... is for the keymanager. Let's use 0x1.
	_ = testRuntime.ID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000001")
	// Empty genesis state root.
	testRuntime.Genesis.StateRoot.Empty()

	// Generate register runtime transaction.
	registerTxPath := filepath.Join(childEnv.Dir(), "registry_runtime_register.json")
	if err = cli.Registry.GenerateRegisterRuntimeTx(childEnv.Dir(), testRuntime, 0, registerTxPath); err != nil {
		return fmt.Errorf("failed to generate runtime register tx: %w", err)
	}

	// Submit register runtime transaction.
	if err = cli.Consensus.SubmitTx(registerTxPath); err != nil {
		return fmt.Errorf("failed to submit runtime register tx: %w", err)
	}

	// List runtimes.
	runtimes, err = sc.listRuntimes(childEnv, false)
	if err != nil {
		return err
	}
	// Our new runtime should also be registered now.
	if len(runtimes) != 1 {
		return fmt.Errorf("wrong number of runtimes: %d, expected: %d. Runtimes: %v", len(runtimes), 1, runtimes)
	}

	// Compare runtime descriptors.
	rt := runtimes[testRuntime.ID]
	rtStr, _ := json.Marshal(rt)
	testRuntimeStr, _ := json.Marshal(testRuntime)
	if !bytes.Equal(rtStr, testRuntimeStr) {
		return fmt.Errorf("runtime %s does not match the test one. registry one: %s, test one: %s", testRuntime.ID.String(), rtStr, testRuntimeStr)
	}

	// Wait for runtime to suspend.
	if err = sc.Net.Controller().SetEpoch(ctx, 1); err != nil {
		return fmt.Errorf("failed to set epoch to %d: %w", 1, err)
	}

	// List runtimes.
	runtimes, err = sc.listRuntimes(childEnv, false)
	if err != nil {
		return err
	}
	// Make sure runtime is suspended.
	if len(runtimes) != 0 {
		return fmt.Errorf("wrong number of runtimes: %d, expected: %d. Runtimes: %v", len(runtimes), 1, runtimes)
	}

	allRuntimes, err := sc.listRuntimes(childEnv, true)
	if err != nil {
		return err
	}
	// Make sure suspended runtime is included.
	if len(allRuntimes) != 1 {
		return fmt.Errorf("wrong number of runtimes: %d, expected: %d. Runtimes: %v", len(runtimes), 1, runtimes)
	}

	return nil
}

// listRuntimes lists currently registered runtimes.
func (sc *registryCLIImpl) listRuntimes(childEnv *env.Env, includeSuspended bool) (map[common.Namespace]registry.Runtime, error) {
	sc.Logger.Info("listing all runtimes")
	args := []string{
		"registry", "runtime", "list",
		"-v",
		"--" + grpc.CfgAddress, "unix:" + sc.Net.Validators()[0].SocketPath(),
	}
	if includeSuspended {
		args = append(args, "--"+cmdRegRuntime.CfgIncludeSuspended)
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "list", sc.Net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("failed to list runtimes: error: %w output: %s", err, out.String())
	}

	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	runtimes := map[common.Namespace]registry.Runtime{}
	for {
		var rt registry.Runtime
		if err = dec.Decode(&rt); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		runtimes[rt.ID] = rt
	}

	return runtimes, nil
}
