package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/consensus"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdRegEnt "github.com/oasislabs/oasis-core/go/oasis-node/cmd/registry/entity"
	cmdRegNode "github.com/oasislabs/oasis-core/go/oasis-node/cmd/registry/node"
	cmdRegRt "github.com/oasislabs/oasis-core/go/oasis-node/cmd/registry/runtime"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

const ()

var (
	// RegistryCLI is the staking scenario.
	RegistryCLI scenario.Scenario = &registryCLIImpl{
		basicImpl: basicImpl{},
		logger:    logging.GetLogger("scenario/e2e/registry"),
	}
)

type registryCLIImpl struct {
	basicImpl

	logger *logging.Logger
}

func (r *registryCLIImpl) Name() string {
	return "registry-cli"
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

	// Run the tests
	// registry entity and registry node subcommands
	if err := r.testEntityAndNode(childEnv); err != nil {
		return fmt.Errorf("scenario/e2e/registry: error while running registry entity and node test: %w", err)
	}

	// registry runtime subcommands
	if err := r.testRuntime(childEnv); err != nil {
		return fmt.Errorf("scenario/e2e/registry: error while running registry runtime test: %w", err)
	}

	// Stop the network.
	r.logger.Info("stopping the network")
	r.net.Stop()

	return nil
}

// testEntity tests registry entity subcommands.
func (r *registryCLIImpl) testEntityAndNode(childEnv *env.Env) error {
	// List entities.
	entities, err := r.listEntities(childEnv)
	if err != nil {
		return err
	}
	// Two entities should be registered in our genesis block.
	if len(entities) != 2 {
		return fmt.Errorf("scenario/e2e/registry: initial entity list wrong number of entities: %d, expected at least: %d. Entities: %s", len(entities), 2, entities)
	}

	// List nodes.
	nodes, err := r.listNodes(childEnv)
	if err != nil {
		return err
	}
	// Three nodes should be registered in our genesis block initially.
	if len(nodes) != 3 {
		return fmt.Errorf("scenario/e2e/registry: initial node list wrong number of nodes: %d, expected at least: %d. Nodes: %s", len(nodes), 3, nodes)
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
		return fmt.Errorf("scenario/e2e/registry/entity: got empty entity after updating")
	}
	// Check whether the entity was updated.
	entBinary, _ := json.Marshal(ent)
	entUpBinary, _ := json.Marshal(entUp)
	if bytes.Equal(entBinary, entUpBinary) {
		return fmt.Errorf("scenario/e2e/registry/entity: update entity failed. Entity not changed: %s", string(entBinary))
	}
	if len(entUp.Nodes) != 1 {
		return fmt.Errorf("scenario/e2e/registry/entity: update entity failed. Wrong number of nodes: %d. Expected %d", len(entUp.Nodes), 1)
	}
	if !entUp.Nodes[0].Equal(n.ID) {
		return fmt.Errorf("scenario/e2e/registry/entity: update entity failed. Wrong node ID: %s. Expected %s", entUp.Nodes[0].String(), n.ID.String())
	}

	// Generate register entity transaction.
	registerTxPath := filepath.Join(childEnv.Dir(), "registry_entity_register.json")
	if err = r.genRegisterEntityTx(childEnv, 0, registerTxPath, entDir.String()); err != nil {
		return fmt.Errorf("scenario/e2e/registry/entity: failed to generate entity register tx: %w", err)
	}

	// Submit register entity transaction.
	if err = r.submitTx(childEnv, registerTxPath); err != nil {
		return fmt.Errorf("scenario/e2e/registry/entity: failed to submit entity register tx: %w", err)
	}

	// List entities.
	entities, err = r.listEntities(childEnv)
	if err != nil {
		return err
	}
	// Three entities should now be registered after registration.
	if len(entities) != 3 {
		return fmt.Errorf("scenario/e2e/registry: initial entity list wrong number of entities: %d, expected at least: %d. Entities: %s", len(entities), 3, entities)
	}

	// Generate deregister entity transaction.
	deregisterTxPath := filepath.Join(childEnv.Dir(), "registry_entity_deregister.json")
	if err = r.genDeregisterEntityTx(childEnv, 1, deregisterTxPath, entDir.String()); err != nil {
		return fmt.Errorf("scenario/e2e/registry/entity: failed to generate entity deregister tx: %w", err)
	}

	// Submit deregister entity transaction.
	if err = r.submitTx(childEnv, deregisterTxPath); err != nil {
		return fmt.Errorf("scenario/e2e/registry/entity: failed to submit entity deregister tx: %w", err)
	}

	// List entities.
	entities, err = r.listEntities(childEnv)
	if err != nil {
		return err
	}
	// Only two entities should now be registered after deregistration.
	if len(entities) != 2 {
		return fmt.Errorf("scenario/e2e/registry: initial entity list wrong number of entities: %d, expected at least: %d. Entities: %s", len(entities), 2, entities)
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
	b, err := runSubCommandWithOutput(childEnv, "list", r.basicImpl.net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("scenario/e2e/registry/entity: failed to list entities: %s error: %w", b.String(), err)
	}
	entitiesStr := strings.Split(b.String(), "\n")

	var entities []signature.PublicKey
	for _, entStr := range entitiesStr {
		// Ignore last newline.
		if entStr == "" {
			continue
		}

		var ent signature.PublicKey
		if err = ent.UnmarshalHex(entStr); err != nil {
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
		return nil, fmt.Errorf("failed to load entity: %s", err)
	}

	return ent, nil
}

// initEntity initializes new entity.
func (r *registryCLIImpl) initEntity(childEnv *env.Env, entDir string) (*entity.Entity, error) {
	r.logger.Info("initializing new entity")

	args := []string{
		"registry", "entity", "init",
		"--" + common.CfgDataDir, entDir,
	}
	_, err := runSubCommandWithOutput(childEnv, "entity-init", r.basicImpl.net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("scenario/e2e/registry/entity: failed to init entity: %w", err)
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
		"--" + common.CfgDataDir, entDir,
		"--" + cmdRegEnt.CfgNodeID, strings.Join(nodeIDs, ","),
		"--" + cmdRegEnt.CfgNodeDescriptor, strings.Join(nodeGenesisFiles, ","),
	}
	_, err := runSubCommandWithOutput(childEnv, "entity-update", r.basicImpl.net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("scenario/e2e/registry/entity: failed to update entity: %w", err)
	}

	return r.loadEntity(entDir)
}

// listEntities lists currently registered entities.
func (r *registryCLIImpl) listNodes(childEnv *env.Env) ([]signature.PublicKey, error) {
	r.logger.Info("listing all nodes")
	args := []string{
		"registry", "node", "list",
		"--" + grpc.CfgAddress, "unix:" + r.basicImpl.net.Validators()[0].SocketPath(),
	}
	b, err := runSubCommandWithOutput(childEnv, "node-list", r.basicImpl.net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("scenario/e2e/registry/entity: failed to list nodes: %s error: %w", b.String(), err)
	}
	nodesStr := strings.Split(b.String(), "\n")

	var nodes []signature.PublicKey
	for _, accStr := range nodesStr {
		// Ignore last newline.
		if accStr == "" {
			continue
		}

		var acc signature.PublicKey
		if err = acc.UnmarshalHex(accStr); err != nil {
			return nil, err
		}
		nodes = append(nodes, acc)
	}

	return nodes, nil
}

// newTestNode returns a test node instance given the entityID.
func (r *registryCLIImpl) newTestNode(entityID signature.PublicKey) (*node.Node, []string, []string, error) {
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
	testCAddresses := []node.ConsensusAddress{
		{
			ID: signature.PublicKey{},
			Address: node.Address{TCPAddr: net.TCPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 12345,
				Zone: "",
			}},
		},
		{
			ID: signature.PublicKey{},
			Address: node.Address{TCPAddr: net.TCPAddr{
				IP:   net.IPv4(127, 0, 0, 2),
				Port: 54321,
				Zone: "",
			}},
		},
	}
	_ = testCAddresses[0].ID.UnmarshalHex("1100000000000000000000000000000000000000000000000000000000000000")
	_ = testCAddresses[1].ID.UnmarshalHex("1200000000000000000000000000000000000000000000000000000000000000")
	testCAddressesStr := []string{}
	for _, a := range testCAddresses {
		testCAddressesStr = append(testCAddressesStr, a.String())
	}
	testNode := node.Node{
		ID:         signature.PublicKey{}, // ID is generated afterwards.
		EntityID:   entityID,
		Expiration: 42,
		Committee: node.CommitteeInfo{
			Certificate: []byte{}, // Certificate is generated afterwards.
			Addresses:   testAddresses,
		},
		P2P: node.P2PInfo{
			ID:        signature.PublicKey{}, // ID is generated afterwards.
			Addresses: testAddresses,
		},
		Consensus: node.ConsensusInfo{
			ID:        signature.PublicKey{}, // ID is generated afterwards.
			Addresses: testCAddresses,
		},
		Runtimes: []*node.Runtime{
			{
				ID: signature.PublicKey{}, // ID is set below.
			},
		},
		Roles: node.RoleValidator,
	}
	_ = testNode.Runtimes[0].ID.UnmarshalHex("4000000000000000000000000000000000000000000000000000000000000000")

	return &testNode, testAddressesStr, testCAddressesStr, nil
}

// initNode very "thoroughly" initializes new node and returns its instance.
func (r *registryCLIImpl) initNode(childEnv *env.Env, ent *entity.Entity, entDir string, dataDir string) (*node.Node, error) {
	r.logger.Info("initializing new entity")

	// testNode will be our fixture for testing the CLI.
	testNode, testAddressesStr, testCAddressesStr, err := r.newTestNode(ent.ID)
	if err != nil {
		return nil, err
	}

	// Helper for running the cmd and importing the generated node instance.
	runInitNode := func() (*node.Node, error) {
		args := []string{
			"registry", "node", "init",
			"--" + cmdRegNode.CfgCommitteeAddress, strings.Join(testAddressesStr, ","),
			"--" + cmdRegNode.CfgConsensusAddress, strings.Join(testCAddressesStr, ","),
			"--" + cmdRegNode.CfgEntityID, testNode.EntityID.String(),
			"--" + cmdRegNode.CfgExpiration, strconv.FormatUint(testNode.Expiration, 10),
			"--" + cmdRegNode.CfgSelfSigned, "1",
			"--" + cmdRegNode.CfgP2PAddress, strings.Join(testAddressesStr, ","),
			"--" + cmdRegNode.CfgRole, testNode.Roles.String(),
			"--" + cmdRegNode.CfgNodeRuntimeID, testNode.Runtimes[0].ID.String(),
			"--" + flags.CfgEntity, entDir,
			"--" + common.CfgDataDir, dataDir,
		}
		_, err = runSubCommandWithOutput(childEnv, "init-node", r.basicImpl.net.Config().NodeBinary, args)
		if err != nil {
			return nil, fmt.Errorf("scenario/e2e/registry: failed to init node: %w", err)
		}

		// Check, if node genesis file was correctly written.
		var b []byte
		if b, err = ioutil.ReadFile(filepath.Join(dataDir, cmdRegNode.NodeGenesisFilename)); err != nil {
			return nil, fmt.Errorf("scenario/e2e/registry: failed to open node genesis file: %w", err)
		}

		var signedNode node.SignedNode
		if err = json.Unmarshal(b, &signedNode); err != nil {
			return nil, fmt.Errorf("scenario/e2e/registry: failed to unmarshal signed node: %w", err)
		}

		var n node.Node
		if err = signedNode.Open(registry.RegisterGenesisNodeSignatureContext, &n); err != nil {
			return nil, fmt.Errorf("scenario/e2e/registry: failed to validate signed node descriptor: %w", err)
		}

		return &n, nil
	}

	n, err := runInitNode()
	if err != nil {
		return nil, err
	}

	// Check the generated fields from imported node.
	if !n.ID.IsValid() {
		return nil, fmt.Errorf("scenario/e2e/registry: new node ID is not valid")
	}
	if n.Committee.Certificate == nil || len(n.Committee.Certificate) == 0 {
		return nil, fmt.Errorf("scenario/e2e/registry: new node committee certificate is not set")
	}
	if !n.P2P.ID.IsValid() {
		return nil, fmt.Errorf("scenario/e2e/registry: new node P2P ID is not valid")
	}
	if !n.Consensus.ID.IsValid() {
		return nil, fmt.Errorf("scenario/e2e/registry: new node Consensus ID is not valid")
	}

	// Replace our testNode fields with the generated one, so we can just marshal both nodes and compare the output afterwards.
	testNode.ID = n.ID
	testNode.Committee.Certificate = n.Committee.Certificate
	testNode.P2P.ID = n.P2P.ID
	testNode.Consensus.ID = n.Consensus.ID

	// Export both original and imported node to JSON and compare them.
	nStr, _ := json.Marshal(n)
	testNodeStr, _ := json.Marshal(testNode)
	if !bytes.Equal(nStr, testNodeStr) {
		return nil, fmt.Errorf("scenario/e2e/registry: test node mismatch! Original node: %s, imported node: %s", testNodeStr, nStr)
	}

	// Now run node init again, this time by reading existing dataDir and expect the same node identity and JSON output.
	if err = os.Remove(filepath.Join(dataDir, cmdRegNode.NodeGenesisFilename)); err != nil {
		return nil, fmt.Errorf("scenario/e2e/registry: error while removing test node genesis file: %w", err)
	}
	n, err = runInitNode()
	if err != nil {
		return nil, err
	}
	nStr, _ = json.Marshal(n)
	if !bytes.Equal(nStr, testNodeStr) {
		return nil, fmt.Errorf("scenario/e2e/registry: second run test node mismatch! Original node: %s, imported node: %s", testNodeStr, nStr)
	}

	return n, nil
}

// submitTx is a wrapper for consensus submit_tx command.
func (r *registryCLIImpl) submitTx(childEnv *env.Env, txPath string) error {
	return submitTx(childEnv, txPath, r.logger, r.basicImpl.net.Validators()[0].SocketPath(), r.basicImpl.net.Config().NodeBinary)
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
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgEntity, entDir,
		"--" + flags.CfgGenesisFile, r.basicImpl.net.GenesisPath(),
	}
	if err := runSubCommand(childEnv, "gen_register", r.basicImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genRegisterEntityTx: failed to generate register entity tx: %w", err)
	}

	return nil
}

// genDeregisterEntityTx calls registry entity gen_deregister.
func (r *registryCLIImpl) genDeregisterEntityTx(childEnv *env.Env, nonce int, txPath string, entDir string) error {
	r.logger.Info("generating register entity tx")

	args := []string{
		"registry", "entity", "gen_deregister",
		"--" + consensus.CfgTxNonce, strconv.Itoa(nonce),
		"--" + consensus.CfgTxFile, txPath,
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(0),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgEntity, entDir,
		"--" + flags.CfgGenesisFile, r.basicImpl.net.GenesisPath(),
	}
	if err := runSubCommand(childEnv, "gen_deregister", r.basicImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genDeregisterEntityTx: failed to generate deregister entity tx: %w", err)
	}

	return nil
}

// testRuntime tests registry runtime subcommands.
func (r *registryCLIImpl) testRuntime(childEnv *env.Env) error {
	// List runtimes.
	runtimes, err := r.listRuntimes(childEnv)
	if err != nil {
		return err
	}
	// simple-client and keymanager runtime should be registered in our genesis block.
	if len(runtimes) != 2 {
		return fmt.Errorf("scenario/e2e/registry: initial runtime list wrong number of runtimes: %d, expected at least: %d. Runtimes: %v", len(runtimes), 2, runtimes)
	}

	// Create runtime descriptor instance.
	testRuntime := registry.Runtime{
		Kind: registry.KindCompute,
		Compute: registry.ComputeParameters{
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
		Storage: registry.StorageParameters{
			GroupSize: 9,
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			GroupSize:         10,
			Algorithm:         "batching",
			BatchFlushTimeout: 11 * time.Second,
			MaxBatchSize:      12,
			MaxBatchSizeBytes: 13,
		},
	}
	// Runtime ID 0x0 is for simple-keyvalue, 0xf... is for the keymanager. Let's use 0x1.
	_ = testRuntime.ID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000001")
	testRuntime.KeyManagerOpt = &signature.PublicKey{}
	_ = testRuntime.KeyManagerOpt.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")

	// Generate register runtime transaction.
	registerTxPath := filepath.Join(childEnv.Dir(), "registry_runtime_register.json")
	genesisStatePath := filepath.Join(childEnv.Dir(), "registry_runtime_register_genesis_state.json")
	genesisStateStr, _ := json.Marshal(testRuntime.Genesis.State)
	if err = ioutil.WriteFile(genesisStatePath, genesisStateStr, 0600); err != nil {
		return err
	}
	if err = r.genRegisterRuntimeTx(childEnv, testRuntime, registerTxPath, genesisStatePath); err != nil {
		return fmt.Errorf("scenario/e2e/registry/runtime: failed to generate runtime register tx: %w", err)
	}

	// Submit register runtime transaction.
	if err = r.submitTx(childEnv, registerTxPath); err != nil {
		return fmt.Errorf("scenario/e2e/registry/runtime: failed to submit runtime register tx: %w", err)
	}

	// List runtimes.
	runtimes, err = r.listRuntimes(childEnv)
	if err != nil {
		return err
	}
	// Our new runtime should also be registered now.
	if len(runtimes) != 3 {
		return fmt.Errorf("scenario/e2e/registry: initial runtime list wrong number of runtimes: %d, expected at least: %d. Runtimes: %v", len(runtimes), 3, runtimes)
	}

	// Compare runtime descriptors.
	rt := runtimes[testRuntime.ID]
	rtStr, _ := json.Marshal(rt)
	testRuntimeStr, _ := json.Marshal(testRuntime)
	if !bytes.Equal(rtStr, testRuntimeStr) {
		return fmt.Errorf("scenario/e2e/registry: runtime %s does not match the test one. registry one: %s, test one: %s", testRuntime.ID.String(), rtStr, testRuntimeStr)
	}

	return nil
}

// listRuntimes lists currently registered runtimes.
func (r *registryCLIImpl) listRuntimes(childEnv *env.Env) (map[signature.PublicKey]registry.Runtime, error) {
	r.logger.Info("listing all runtimes")
	args := []string{
		"registry", "runtime", "list",
		"-v",
		"--" + grpc.CfgAddress, "unix:" + r.basicImpl.net.Validators()[0].SocketPath(),
	}
	b, err := runSubCommandWithOutput(childEnv, "list", r.basicImpl.net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("scenario/e2e/registry/runtime: failed to list runtimes: %s error: %w", b.String(), err)
	}
	runtimesStr := strings.Split(b.String(), "\n")

	runtimes := map[signature.PublicKey]registry.Runtime{}
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

// genRegisterRuntimeTx calls registry entity gen_register.
func (r *registryCLIImpl) genRegisterRuntimeTx(childEnv *env.Env, runtime registry.Runtime, txPath string, genesisStateFile string) error {
	r.logger.Info("generating register entity tx")

	// Generate a runtime register transaction file with debug test entity.
	args := []string{
		"registry", "runtime", "gen_register",
		"--" + cmdRegRt.CfgID, runtime.ID.String(),
		"--" + cmdRegRt.CfgTEEHardware, runtime.TEEHardware.String(),
		"--" + cmdRegRt.CfgGenesisState, genesisStateFile,
		"--" + cmdRegRt.CfgKind, runtime.Kind.String(),
		"--" + cmdRegRt.CfgVersion, runtime.Version.Version.String(),
		"--" + cmdRegRt.CfgVersionEnclave, string(runtime.Version.TEE),
		"--" + cmdRegRt.CfgComputeGroupSize, strconv.FormatUint(runtime.Compute.GroupSize, 10),
		"--" + cmdRegRt.CfgComputeGroupBackupSize, strconv.FormatUint(runtime.Compute.GroupBackupSize, 10),
		"--" + cmdRegRt.CfgComputeAllowedStragglers, strconv.FormatUint(runtime.Compute.AllowedStragglers, 10),
		"--" + cmdRegRt.CfgComputeRoundTimeout, runtime.Compute.RoundTimeout.String(),
		"--" + cmdRegRt.CfgMergeGroupSize, strconv.FormatUint(runtime.Merge.GroupSize, 10),
		"--" + cmdRegRt.CfgMergeGroupBackupSize, strconv.FormatUint(runtime.Merge.GroupBackupSize, 10),
		"--" + cmdRegRt.CfgMergeAllowedStragglers, strconv.FormatUint(runtime.Merge.AllowedStragglers, 10),
		"--" + cmdRegRt.CfgMergeRoundTimeout, runtime.Merge.RoundTimeout.String(),
		"--" + cmdRegRt.CfgStorageGroupSize, strconv.FormatUint(runtime.Storage.GroupSize, 10),
		"--" + cmdRegRt.CfgTxnSchedulerGroupSize, strconv.FormatUint(runtime.TxnScheduler.GroupSize, 10),
		"--" + cmdRegRt.CfgTxnSchedulerAlgorithm, runtime.TxnScheduler.Algorithm,
		"--" + cmdRegRt.CfgTxnSchedulerBatchFlushTimeout, runtime.TxnScheduler.BatchFlushTimeout.String(),
		"--" + cmdRegRt.CfgTxnSchedulerMaxBatchSize, strconv.FormatUint(runtime.TxnScheduler.MaxBatchSize, 10),
		"--" + cmdRegRt.CfgTxnSchedulerMaxBatchSizeBytes, strconv.FormatUint(runtime.TxnScheduler.MaxBatchSizeBytes, 10),
		"--" + consensus.CfgTxNonce, strconv.Itoa(0),
		"--" + consensus.CfgTxFile, txPath,
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(0),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgDebugTestEntity,
		"--" + flags.CfgGenesisFile, r.basicImpl.net.GenesisPath(),
	}
	if runtime.KeyManagerOpt != nil {
		args = append(args, "--"+cmdRegRt.CfgKeyManager, runtime.KeyManagerOpt.String())
	}
	if err := runSubCommand(childEnv, "gen_register", r.basicImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genRegisterRuntimeTx: failed to generate register runtime tx: %w", err)
	}

	return nil
}
