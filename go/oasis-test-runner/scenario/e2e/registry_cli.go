package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/node"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/consensus"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdRegEnt "github.com/oasislabs/oasis-core/go/oasis-node/cmd/registry/entity"
	cmdRegNode "github.com/oasislabs/oasis-core/go/oasis-node/cmd/registry/node"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

var (
	// RegistryCLI is the staking scenario.
	RegistryCLI scenario.Scenario = &registryCLIImpl{
		basicImpl: *newBasicImpl("registry-cli", "", nil),
	}
)

type registryCLIImpl struct {
	basicImpl
}

func (r *registryCLIImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := r.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// We will mock epochs for reclaiming the escrow.
	f.Network.EpochtimeMock = true

	// Allow runtime registration.
	f.Network.RegistryDebugAllowRuntimeRegistration = true

	return f, nil
}

func (r *registryCLIImpl) Run(childEnv *env.Env) error {
	if err := r.net.Start(); err != nil {
		return err
	}

	ctx := context.Background()
	logger.Info("waiting for nodes to register")
	if err := r.net.Controller().WaitNodesRegistered(ctx, 3); err != nil {
		return fmt.Errorf("waiting for nodes to register: %w", err)
	}
	logger.Info("nodes registered")

	cli := cli.New(childEnv, r.net, r.logger)

	// Run the tests
	// registry entity and registry node subcommands
	if err := r.testEntityAndNode(childEnv, cli); err != nil {
		return fmt.Errorf("scenario/e2e/registry: error while running registry entity and node test: %w", err)
	}

	// registry runtime subcommands
	if err := r.testRuntime(childEnv, cli); err != nil {
		return fmt.Errorf("scenario/e2e/registry: error while running registry runtime test: %w", err)
	}

	// Stop the network.
	r.logger.Info("stopping the network")
	r.net.Stop()

	return nil
}

// testEntity tests registry entity subcommands.
func (r *registryCLIImpl) testEntityAndNode(childEnv *env.Env, cli *cli.Helpers) error {
	// List entities.
	entities, err := r.listEntities(childEnv)
	if err != nil {
		return err
	}
	// Two entities should be registered in our genesis block.
	if len(entities) != 2 {
		return fmt.Errorf("initial entity list wrong number of entities: %d, expected at least: %d. Entities: %s", len(entities), 2, entities)
	}

	// List nodes.
	nodes, err := r.listNodes(childEnv)
	if err != nil {
		return err
	}
	// Three nodes should be registered in our genesis block initially.
	if len(nodes) != 3 {
		return fmt.Errorf("initial node list wrong number of nodes: %d, expected at least: %d. Nodes: %s", len(nodes), 3, nodes)
	}

	// Init new entity.
	entDir, err := childEnv.NewSubDir("entity")
	if err != nil {
		return err
	}

	var ent *entity.Entity
	ent, err = r.initEntity(childEnv, entDir.String())
	if err != nil {
		return err
	}

	// Init new node.
	nDir, err := childEnv.NewSubDir("node")
	if err != nil {
		return err
	}
	var n *node.Node
	n, err = r.initNode(childEnv, ent, entDir.String(), nDir.String())
	if err != nil {
		return err
	}

	// Update entity with a new node.
	var entUp *entity.Entity
	nodeGenesisFile := nDir.String() + "/node_genesis.json"
	entUp, err = r.updateEntity(childEnv, []*node.Node{n}, []string{nodeGenesisFile}, entDir.String())
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
	if err = r.genRegisterEntityTx(childEnv, 0, registerTxPath, entDir.String()); err != nil {
		return err
	}

	// Submit register entity transaction.
	if err = cli.Consensus.SubmitTx(registerTxPath); err != nil {
		return fmt.Errorf("failed to submit entity register tx: %w", err)
	}

	// List entities.
	entities, err = r.listEntities(childEnv)
	if err != nil {
		return err
	}
	// Three entities should now be registered after registration.
	if len(entities) != 3 {
		return fmt.Errorf("initial entity list wrong number of entities: %d, expected at least: %d. Entities: %s", len(entities), 3, entities)
	}

	// Generate deregister entity transaction.
	deregisterTxPath := filepath.Join(childEnv.Dir(), "registry_entity_deregister.json")
	if err = r.genDeregisterEntityTx(childEnv, 1, deregisterTxPath, entDir.String()); err != nil {
		return err
	}

	// Submit deregister entity transaction.
	if err = cli.Consensus.SubmitTx(deregisterTxPath); err != nil {
		return fmt.Errorf("failed to submit entity deregister tx: %w", err)
	}

	// List entities.
	entities, err = r.listEntities(childEnv)
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
func (r *registryCLIImpl) listEntities(childEnv *env.Env) ([]signature.PublicKey, error) {
	r.logger.Info("listing all entities")
	args := []string{
		"registry", "entity", "list",
		"--" + grpc.CfgAddress, "unix:" + r.basicImpl.net.Validators()[0].SocketPath(),
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, r.logger, "list", r.basicImpl.net.Config().NodeBinary, args)
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
			return nil, err
		}
		entities = append(entities, ent)
	}

	return entities, nil
}

// loadEntity loads entity and signer from given directory.
func (r *registryCLIImpl) loadEntity(entDir string) (*entity.Entity, error) {
	entitySignerFactory := fileSigner.NewFactory(entDir, signature.SignerEntity)
	ent, _, err := entity.Load(entDir, entitySignerFactory)
	if err != nil {
		return nil, fmt.Errorf("failed to load entity: %w", err)
	}

	return ent, nil
}

// initEntity initializes new entity.
func (r *registryCLIImpl) initEntity(childEnv *env.Env, entDir string) (*entity.Entity, error) {
	r.logger.Info("initializing new entity")

	args := []string{
		"registry", "entity", "init",
		"--" + flags.CfgSigner, fileSigner.SignerName,
		"--" + flags.CfgSignerDir, entDir,
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, r.logger, "entity-init", r.basicImpl.net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("failed to init entity: error: %w output: %s", err, out.String())
	}

	return r.loadEntity(entDir)
}

// updateInit updates an entity.
func (r *registryCLIImpl) updateEntity(childEnv *env.Env, nodes []*node.Node, nodeGenesisFiles []string, entDir string) (*entity.Entity, error) {
	r.logger.Info("update entity")

	var nodeIDs []string
	for _, n := range nodes {
		nodeIDs = append(nodeIDs, n.ID.String())
	}

	args := []string{
		"registry", "entity", "update",
		"--" + flags.CfgSigner, fileSigner.SignerName,
		"--" + flags.CfgSignerDir, entDir,
		"--" + cmdRegEnt.CfgNodeID, strings.Join(nodeIDs, ","),
		"--" + cmdRegEnt.CfgNodeDescriptor, strings.Join(nodeGenesisFiles, ","),
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, r.logger, "entity-update", r.basicImpl.net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("failed to update entity: error: %w output: %s", err, out.String())
	}

	return r.loadEntity(entDir)
}

// listNodes lists currently registered nodes.
func (r *registryCLIImpl) listNodes(childEnv *env.Env) ([]signature.PublicKey, error) {
	r.logger.Info("listing all nodes")
	args := []string{
		"registry", "node", "list",
		"--" + grpc.CfgAddress, "unix:" + r.basicImpl.net.Validators()[0].SocketPath(),
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, r.logger, "node-list", r.basicImpl.net.Config().NodeBinary, args)
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

// newTestNode returns a test node instance given the entityID.
func (r *registryCLIImpl) newTestNode(entityID signature.PublicKey) (*node.Node, []string, []string, []string, error) {
	// Addresses.
	testAddresses := []node.Address{
		{TCPAddr: net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 12345,
			Zone: "",
		}},
		{TCPAddr: net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 2),
			Port: 54321,
			Zone: "",
		}},
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

	// Committee addresses.
	testCommitteeAddresses := []node.CommitteeAddress{
		{
			Certificate: []byte{}, // Certificate is generated afterwards.
			Address:     testAddresses[0],
		},
		{
			Certificate: []byte{}, // Certificate is generated afterwards.
			Address:     testAddresses[1],
		},
	}
	testCommitteeAddressesStr := []string{}
	for _, a := range testCommitteeAddresses {
		testCommitteeAddressesStr = append(testCommitteeAddressesStr, a.String())
	}

	testNode := node.Node{
		ID:         signature.PublicKey{}, // ID is generated afterwards.
		EntityID:   entityID,
		Expiration: 42,
		Committee: node.CommitteeInfo{
			Certificate: []byte{}, // Certificate is generated afterwards.
			Addresses:   testCommitteeAddresses,
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
		Roles: node.RoleValidator,
	}
	_ = testNode.Runtimes[0].ID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")

	return &testNode, testAddressesStr, testConsensusAddressesStr, testCommitteeAddressesStr, nil
}

// initNode very "thoroughly" initializes new node and returns its instance.
func (r *registryCLIImpl) initNode(childEnv *env.Env, ent *entity.Entity, entDir string, dataDir string) (*node.Node, error) {
	r.logger.Info("initializing new node")

	// testNode will be our fixture for testing the CLI.
	testNode, testAddressesStr, testConsensusAddressesStr, testCommitteeAddressesStr, err := r.newTestNode(ent.ID)
	if err != nil {
		return nil, err
	}

	// Helper for running the cmd and importing the generated node instance.
	runInitNode := func() (*node.Node, error) {
		args := []string{
			"registry", "node", "init",
			"--" + cmdRegNode.CfgCommitteeAddress, strings.Join(testCommitteeAddressesStr, ","),
			"--" + cmdRegNode.CfgConsensusAddress, strings.Join(testConsensusAddressesStr, ","),
			"--" + cmdRegNode.CfgEntityID, testNode.EntityID.String(),
			"--" + cmdRegNode.CfgExpiration, strconv.FormatUint(testNode.Expiration, 10),
			"--" + cmdRegNode.CfgSelfSigned, "1",
			"--" + cmdRegNode.CfgP2PAddress, strings.Join(testAddressesStr, ","),
			"--" + cmdRegNode.CfgRole, testNode.Roles.String(),
			"--" + cmdRegNode.CfgNodeRuntimeID, testNode.Runtimes[0].ID.String(),
			"--" + flags.CfgSigner, fileSigner.SignerName,
			"--" + flags.CfgSignerDir, entDir,
			"--" + cmdCommon.CfgDataDir, dataDir,
		}
		var out bytes.Buffer
		out, err = cli.RunSubCommandWithOutput(childEnv, r.logger, "init-node", r.basicImpl.net.Config().NodeBinary, args)
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
	if n.Committee.Certificate == nil || len(n.Committee.Certificate) == 0 {
		return nil, errors.New("new node committee certificate is not set")
	}
	if !n.P2P.ID.IsValid() {
		return nil, errors.New("new node P2P ID is not valid")
	}
	if !n.Consensus.ID.IsValid() {
		return nil, errors.New("new node Consensus ID is not valid")
	}

	// Replace our testNode fields with the generated one, so we can just marshal both nodes and compare the output afterwards.
	testNode.ID = n.ID
	testNode.Committee.Certificate = n.Committee.Certificate
	testNode.P2P.ID = n.P2P.ID
	testNode.Consensus.ID = n.Consensus.ID
	for idx := range testNode.Committee.Addresses {
		testNode.Committee.Addresses[idx].Certificate = n.Committee.Certificate
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
	nStr, _ = json.Marshal(n)
	if !bytes.Equal(nStr, testNodeStr) {
		return nil, fmt.Errorf("second run test node mismatch! Original node: %s, imported node: %s", testNodeStr, nStr)
	}

	return n, nil
}

// genRegisterEntityTx calls registry entity gen_register.
func (r *registryCLIImpl) genRegisterEntityTx(childEnv *env.Env, nonce int, txPath string, entDir string) error {
	r.logger.Info("generating register entity tx")

	args := []string{
		"registry", "entity", "gen_register",
		"--" + consensus.CfgTxNonce, strconv.Itoa(nonce),
		"--" + consensus.CfgTxFile, txPath,
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(0),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + cmdCommon.CfgDebugAllowTestKeys,
		"--" + flags.CfgSigner, fileSigner.SignerName,
		"--" + flags.CfgSignerDir, entDir,
		"--" + flags.CfgGenesisFile, r.basicImpl.net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, r.logger, "gen_register", r.basicImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("failed to generate register entity tx: error: %w output: %s", err, out.String())
	}

	return nil
}

// genDeregisterEntityTx calls registry entity gen_deregister.
func (r *registryCLIImpl) genDeregisterEntityTx(childEnv *env.Env, nonce int, txPath string, entDir string) error {
	r.logger.Info("generating deregister entity tx")

	args := []string{
		"registry", "entity", "gen_deregister",
		"--" + consensus.CfgTxNonce, strconv.Itoa(nonce),
		"--" + consensus.CfgTxFile, txPath,
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(0),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + cmdCommon.CfgDebugAllowTestKeys,
		"--" + flags.CfgSigner, fileSigner.SignerName,
		"--" + flags.CfgSignerDir, entDir,
		"--" + flags.CfgGenesisFile, r.basicImpl.net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, r.logger, "gen_deregister", r.basicImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("failed to generate deregister entity tx: error: %w output: %s", err, out.String())
	}

	return nil
}

// testRuntime tests registry runtime subcommands.
func (r *registryCLIImpl) testRuntime(childEnv *env.Env, cli *cli.Helpers) error {
	// List runtimes.
	runtimes, err := r.listRuntimes(childEnv)
	if err != nil {
		return err
	}
	// simple-client and keymanager runtime should be registered in our genesis block.
	if len(runtimes) != 2 {
		return fmt.Errorf("initial runtime list wrong number of runtimes: %d, expected at least: %d. Runtimes: %v", len(runtimes), 2, runtimes)
	}

	// Create runtime descriptor instance.
	testEntity, _, err := entity.TestEntity()
	if err != nil {
		return fmt.Errorf("TestEntity: %w", err)
	}
	testRuntime := registry.Runtime{
		Kind: registry.KindCompute,
		Executor: registry.ExecutorParameters{
			GroupSize:         1,
			GroupBackupSize:   2,
			AllowedStragglers: 3,
			RoundTimeout:      4 * time.Second,
		},
		Merge: registry.MergeParameters{
			GroupSize:         5,
			GroupBackupSize:   6,
			AllowedStragglers: 7,
			RoundTimeout:      8 * time.Second,
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			GroupSize:         10,
			Algorithm:         "batching",
			BatchFlushTimeout: 11 * time.Second,
			MaxBatchSize:      12,
			MaxBatchSizeBytes: 13,
		},
		Storage: registry.StorageParameters{
			GroupSize:               9,
			MaxApplyWriteLogEntries: 10,
			MaxApplyOps:             11,
			MaxMergeRoots:           12,
			MaxMergeOps:             13,
		},
		AdmissionPolicy: registry.RuntimeAdmissionPolicy{
			EntityWhitelist: &registry.EntityWhitelistRuntimeAdmissionPolicy{
				Entities: map[signature.PublicKey]bool{
					testEntity.ID: true,
				},
			},
		},
	}
	// Runtime ID 0x0 is for simple-keyvalue, 0xf... is for the keymanager. Let's use 0x1.
	_ = testRuntime.ID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000001")
	testRuntime.KeyManager = &common.Namespace{}
	_ = testRuntime.KeyManager.UnmarshalHex("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff")
	// Empty genesis state root.
	testRuntime.Genesis.StateRoot.Empty()

	// Generate register runtime transaction.
	registerTxPath := filepath.Join(childEnv.Dir(), "registry_runtime_register.json")
	genesisStatePath := filepath.Join(childEnv.Dir(), "registry_runtime_register_genesis_state.json")
	genesisStateStr, _ := json.Marshal(testRuntime.Genesis.State)
	if err = ioutil.WriteFile(genesisStatePath, genesisStateStr, 0600); err != nil {
		return err
	}
	if err = cli.Registry.GenerateRegisterRuntimeTx(0, testRuntime, registerTxPath, genesisStatePath); err != nil {
		return fmt.Errorf("failed to generate runtime register tx: %w", err)
	}

	// Submit register runtime transaction.
	if err = cli.Consensus.SubmitTx(registerTxPath); err != nil {
		return fmt.Errorf("failed to submit runtime register tx: %w", err)
	}

	// List runtimes.
	runtimes, err = r.listRuntimes(childEnv)
	if err != nil {
		return err
	}
	// Our new runtime should also be registered now.
	if len(runtimes) != 3 {
		return fmt.Errorf("initial runtime list wrong number of runtimes: %d, expected at least: %d. Runtimes: %v", len(runtimes), 3, runtimes)
	}

	// Compare runtime descriptors.
	rt := runtimes[testRuntime.ID]
	rtStr, _ := json.Marshal(rt)
	testRuntimeStr, _ := json.Marshal(testRuntime)
	if !bytes.Equal(rtStr, testRuntimeStr) {
		return fmt.Errorf("runtime %s does not match the test one. registry one: %s, test one: %s", testRuntime.ID.String(), rtStr, testRuntimeStr)
	}

	return nil
}

// listRuntimes lists currently registered runtimes.
func (r *registryCLIImpl) listRuntimes(childEnv *env.Env) (map[common.Namespace]registry.Runtime, error) {
	r.logger.Info("listing all runtimes")
	args := []string{
		"registry", "runtime", "list",
		"-v",
		"--" + grpc.CfgAddress, "unix:" + r.basicImpl.net.Validators()[0].SocketPath(),
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, r.logger, "list", r.basicImpl.net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("failed to list runtimes: error: %w output: %s", err, out.String())
	}
	runtimesStr := strings.Split(out.String(), "\n")

	runtimes := map[common.Namespace]registry.Runtime{}
	for _, rtStr := range runtimesStr {
		// Ignore last newline.
		if rtStr == "" {
			continue
		}

		var rt registry.Runtime
		if err = json.Unmarshal([]byte(rtStr), &rt); err != nil {
			return nil, err
		}
		runtimes[rt.ID] = rt
	}

	return runtimes, nil
}
