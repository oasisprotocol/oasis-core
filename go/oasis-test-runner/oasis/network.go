package oasis

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/genesis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// Network is a test Oasis network.
type Network struct { // nolint: maligned
	logger *logging.Logger

	env     *env.Env
	baseDir *env.Dir
	running bool

	nodes          []*Node
	entities       []*Entity
	validators     []*Validator
	runtimes       []*Runtime
	keymanagers    []*Keymanager
	computeWorkers []*Compute
	sentries       []*Sentry
	clients        []*Client
	byzantine      []*Byzantine
	seeds          []*Seed

	keymanagerPolicies []*KeymanagerPolicy

	iasProxy *iasProxy

	cfg          *NetworkCfg
	nextNodePort uint16

	logWatchers []*log.Watcher

	controller       *Controller
	clientController *Controller

	errCh chan error
}

// IASCfg is the Oasis test network IAS configuration.
type IASCfg struct {
	// Mock specifies if Mock IAS Proxy should be used.
	Mock bool `json:"mock,omitempty"`
}

// NetworkCfg is the Oasis test network configuration.
type NetworkCfg struct { // nolint: maligned
	// GenesisFile is an optional genesis file to use.
	GenesisFile string `json:"genesis_file,omitempty"`

	// NodeBinary is the path to the Oasis node binary.
	NodeBinary string `json:"node_binary"`

	// RuntimeSGXLoaderBinary is the path to the Oasis SGX runtime loader.
	RuntimeSGXLoaderBinary string `json:"runtime_loader_binary"`

	// Consensus are the network-wide consensus parameters.
	Consensus consensusGenesis.Genesis `json:"consensus"`

	// InitialHeight is the initial block height.
	InitialHeight int64 `json:"initial_height,omitempty"`

	// HaltEpoch is the halt epoch height flag.
	HaltEpoch uint64 `json:"halt_epoch"`

	// Beacon is the network-wide beacon parameters.
	Beacon beacon.ConsensusParameters `json:"beacon"`

	// DeterministicIdentities is the deterministic identities flag.
	DeterministicIdentities bool `json:"deterministic_identities"`

	// RestoreIdentities is the restore identities flag.
	RestoreIdentities bool `json:"restore_identities"`

	// FundEntities is the fund entities flag.
	FundEntities bool `json:"fund_entities"`

	// IAS is the Network IAS configuration.
	IAS IASCfg `json:"ias"`

	// StakingGenesis is the staking genesis data to be included if
	// GenesisFile is not set.
	StakingGenesis *staking.Genesis `json:"staking_genesis,omitempty"`

	// GovernanceParameters are the governance consensus parameters.
	GovernanceParameters *governance.ConsensusParameters `json:"governance_parameters,omitempty"`

	// RoothashParameters are the roothash consensus parameters.
	RoothashParameters *roothash.ConsensusParameters `json:"roothash_parameters,omitempty"`

	// SchedulerWeakAlpkaOk is for disabling the VRF alpha entropy requirement.
	SchedulerWeakAlphaOk bool `json:"scheduler_weak_alpha_ok,omitempty"`

	// SchedulerForceElect are the rigged committee elections.
	SchedulerForceElect map[common.Namespace]map[signature.PublicKey]*scheduler.ForceElectCommitteeRole `json:"scheduler_force_elect,omitempty"`

	// A set of log watcher handler factories used by default on all nodes
	// created in this test network.
	DefaultLogWatcherHandlerFactories []log.WatcherHandlerFactory `json:"-"`

	// UseShortGrpcSocketPaths specifies whether nodes should use internal.sock in datadir or
	// externally-provided.
	UseShortGrpcSocketPaths bool `json:"-"`

	// Nodes lists the names of nodes to be created, enabling an N:M mapping between physical node
	// processes and the features they host. If a feature is specified as attached to a node that
	// isn't listed here, a new node will be created automatically, so this list can normally be
	// left empty. Nodes are started in the order in which they appear here (automatically created
	// nodes are appended).
	Nodes []string
}

// SetMockEpoch force-enables the mock epoch time keeping.
func (cfg *NetworkCfg) SetMockEpoch() {
	cfg.Beacon.DebugMockBackend = true
	if cfg.Beacon.InsecureParameters != nil {
		cfg.Beacon.InsecureParameters.Interval = defaultEpochtimeTendermintInterval
	}
}

// SetInsecureBeacon force-enables the insecure (faster) beacon backend.
func (cfg *NetworkCfg) SetInsecureBeacon() {
	cfg.Beacon.Backend = beacon.BackendInsecure
	if cfg.Beacon.InsecureParameters != nil {
		cfg.Beacon.InsecureParameters.Interval = defaultEpochtimeTendermintInterval
	}
}

// Config returns the network configuration.
func (net *Network) Config() *NetworkCfg {
	return net.cfg
}

// Entities returns the entities associated with the network.
func (net *Network) Entities() []*Entity {
	return net.entities
}

// Validators returns the validators associated with the network.
func (net *Network) Validators() []*Validator {
	return net.validators
}

// Runtimes returns the runtimes associated with the network.
func (net *Network) Runtimes() []*Runtime {
	return net.runtimes
}

// Seeds returns the seed node associated with the network.
func (net *Network) Seeds() []*Seed {
	return net.seeds
}

// Keymanagers returns the keymanagers associated with the network.
func (net *Network) Keymanagers() []*Keymanager {
	return net.keymanagers
}

// ComputeWorkers returns the compute worker nodes associated with the network.
func (net *Network) ComputeWorkers() []*Compute {
	return net.computeWorkers
}

// Sentries returns the sentry nodes associated with the network.
func (net *Network) Sentries() []*Sentry {
	return net.sentries
}

// Clients returns the client nodes associated with the network.
func (net *Network) Clients() []*Client {
	return net.clients
}

// Byzantine returns the byzantine nodes associated with the network.
func (net *Network) Byzantine() []*Byzantine {
	return net.byzantine
}

// Nodes returns all the validator, compute, storage, keymanager and client nodes associated with
// the network.
//
// Seed, sentry, byzantine and IAS proxy nodes are omitted if they're only hosting these single features.
func (net *Network) Nodes() []*Node {
	// Ignore net.nodes, since it contains too much.
	var nodes []*Node
	for _, v := range net.Validators() {
		nodes = append(nodes, v.Node)
	}
	for _, c := range net.ComputeWorkers() {
		nodes = append(nodes, c.Node)
	}
	for _, k := range net.Keymanagers() {
		nodes = append(nodes, k.Node)
	}
	for _, v := range net.Clients() {
		nodes = append(nodes, v.Node)
	}
	return nodes
}

// GetNamedNode retrieves the node object for the node with the given name and loads
// the given node config into it. If no node with the given name exists, a new
// one is created.
func (net *Network) GetNamedNode(defaultName string, cfg *NodeCfg) (*Node, error) {
	name := defaultName
	if cfg != nil && cfg.Name != "" {
		name = cfg.Name
	}

	var node *Node
	for _, n := range net.nodes {
		if n.Name == name {
			node = n
			break
		}
	}
	newNode := node == nil
	if node == nil {
		nodeDir, err := net.baseDir.NewSubDir(name)
		if err != nil {
			net.logger.Error("failed to create node subdir",
				"err", err,
				"node_name", name,
			)
			return nil, fmt.Errorf("oasis/network: failed to create node subdir: %w", err)
		}

		node = &Node{
			Name:           name,
			net:            net,
			dir:            nodeDir,
			assignedPorts:  map[string]uint16{},
			hostedRuntimes: map[common.Namespace]*hostedRuntime{},
		}

		net.nodes = append(net.nodes, node)
	}

	if cfg != nil {
		cfg.Into(node)
		if newNode {
			if err := net.AddLogWatcher(node); err != nil {
				net.logger.Error("failed to add log watcher",
					"err", err,
					"node_name", name,
				)
				return nil, fmt.Errorf("oasis/network: failed to add log watcher for %s: %w", name, err)
			}
		}
	}
	return node, nil
}

// Errors returns the channel by which node failures will be conveyed.
func (net *Network) Errors() <-chan error {
	return net.errCh
}

// Controller returns the network controller.
func (net *Network) Controller() *Controller {
	return net.controller
}

// ClientController returns the client controller connected to the first client node.
func (net *Network) ClientController() *Controller {
	return net.clientController
}

// SetClientController sets the client controller.
func (net *Network) SetClientController(ctrl *Controller) {
	net.clientController = ctrl
}

// NumRegisterNodes returns the number of all nodes that need to register.
func (net *Network) NumRegisterNodes() int {
	return len(net.validators) +
		len(net.keymanagers) +
		len(net.computeWorkers) +
		len(net.byzantine)
}

// AddLogWatcher adds a log watcher for the given node and creates log watcher
// handlers from the networks's default and node's specific log watcher handler
// factories.
func (net *Network) AddLogWatcher(node *Node) error {
	var logWatcherHandlers []log.WatcherHandler
	// Add network's default log watcher handlers.
	if !node.disableDefaultLogWatcherHandlerFactories {
		for _, logWatcherHandlerFactory := range net.cfg.DefaultLogWatcherHandlerFactories {
			logWatcherHandler, err := logWatcherHandlerFactory.New()
			if err != nil {
				return err
			}
			logWatcherHandlers = append(logWatcherHandlers, logWatcherHandler)
		}
	}
	// Add node's specific log watcher handlers.
	for _, logWatcherHandlerFactory := range node.logWatcherHandlerFactories {
		logWatcherHandler, err := logWatcherHandlerFactory.New()
		if err != nil {
			return err
		}
		logWatcherHandlers = append(logWatcherHandlers, logWatcherHandler)
	}
	logFileWatcher, err := log.NewWatcher(&log.WatcherConfig{
		Name:     fmt.Sprintf("%s/log", node.Name),
		File:     nodeLogPath(node.dir),
		Handlers: logWatcherHandlers,
	})
	if err != nil {
		return err
	}
	net.env.AddOnCleanup(logFileWatcher.Cleanup)
	net.logWatchers = append(net.logWatchers, logFileWatcher)
	return nil
}

// CheckLogWatchers closes all log watchers and checks if any errors were reported
// while the log watchers were running.
func (net *Network) CheckLogWatchers() (err error) {
	for _, w := range net.logWatchers {
		w.Cleanup()
		if logErr := <-w.Errors(); logErr != nil {
			net.logger.Error("log watcher reported error",
				"name", w.Name(),
				"err", logErr,
			)
			err = fmt.Errorf("log watcher %s: %w", w.Name(), logErr)
		}
	}
	return
}

// Start starts the network.
func (net *Network) Start() error { // nolint: gocyclo
	if net.running {
		return nil
	}

	net.logger.Info("starting network")

	// Figure out if the IAS proxy is needed by peeking at all the
	// runtimes.
	for _, v := range net.Runtimes() {
		needIASProxy := v.teeHardware == node.TEEHardwareIntelSGX
		if needIASProxy {
			if _, err := net.newIASProxy(); err != nil {
				net.logger.Error("failed to provision IAS proxy",
					"err", err,
				)
				return err
			}
			break
		}
	}

	if net.cfg.GenesisFile == "" {
		net.logger.Debug("provisioning genesis doc")
		if err := net.MakeGenesis(); err != nil {
			net.logger.Error("failed to create genesis document",
				"err", err,
			)
			return err
		}
	} else {
		net.logger.Debug("using existing genesis doc",
			"path", net.cfg.GenesisFile,
		)
	}

	// Retrieve the genesis document and use it to configure the context for
	// signature domain separation.
	genesisProvider, err := genesisFile.NewFileProvider(net.GenesisPath())
	if err != nil {
		net.logger.Error("failed to load genesis file",
			"err", err,
		)
		return err
	}
	genesisDoc, err := genesisProvider.GetGenesisDocument()
	if err != nil {
		net.logger.Error("failed to retrieve genesis document",
			"err", err,
		)
		return err
	}
	// NOTE: We need to reset the chain context here as E2E tests can run
	//       with different genesis documents which would change the context.
	signature.UnsafeResetChainContext()
	genesisDoc.SetChainContext()

	var iasNodeName string

	net.logger.Debug("starting IAS proxy node")
	if net.iasProxy != nil {
		if err = net.iasProxy.Start(); err != nil {
			net.logger.Error("failed to start IAS proxy node",
				"err", err,
			)
			return err
		}
		iasNodeName = net.iasProxy.Name
	}

	net.logger.Debug("starting network nodes")
	for _, n := range net.nodes {
		if n.Name == iasNodeName {
			continue
		}
		if n.noAutoStart {
			net.logger.Debug("skipping non-autostartable node", "name", n.Name)
			continue
		}
		net.logger.Debug("starting node", "name", n.Name)
		if err = n.Start(); err != nil {
			net.logger.Error("failed to start node",
				"name", n.Name,
				"err", err,
			)
			return err
		}

		// HACK HACK HACK HACK HACK
		//
		// If you don't attempt to start the Tendermint Prometheus HTTP server
		// (even if it is doomed to fail due to node already listening on the
		// port), and you launch all the validators near simultaneously, there
		// is a high chance that at least one of the validators will get upset
		// and start refusing connections.
		if n.hasValidators {
			time.Sleep(validatorStartDelay)
		}
	}

	// Use the first started validator as a controller.
	for _, v := range net.validators {
		if v.noAutoStart {
			continue
		}

		if net.controller, err = NewController(v.SocketPath()); err != nil {
			net.logger.Error("failed to create controller",
				"err", err,
			)
			return fmt.Errorf("oasis: failed to create controller: %w", err)
		}
		break
	}

	// Create a client controller for the first started client node.
	for _, v := range net.clients {
		if v.noAutoStart {
			continue
		}

		if net.clientController, err = NewController(v.SocketPath()); err != nil {
			net.logger.Error("failed to create client controller",
				"err", err,
			)
			return fmt.Errorf("oasis: failed to create client controller: %w", err)
		}
		break
	}

	net.logger.Info("network started")
	net.running = true

	return nil
}

// Stop stops the network.
func (net *Network) Stop() {
	net.env.Cleanup()
	net.running = false
}

func (net *Network) runNodeBinary(consoleWriter io.Writer, args ...string) error {
	nodeBinary := net.cfg.NodeBinary
	cmd := exec.Command(nodeBinary, args...)
	cmd.SysProcAttr = env.CmdAttrs
	if consoleWriter != nil {
		cmd.Stdout = consoleWriter
		cmd.Stderr = consoleWriter
	}

	net.logger.Info("launching node",
		"args", strings.Join(args, " "),
	)

	return cmd.Run()
}

func (net *Network) generateDeterministicIdentity(dir *env.Dir, rawSeed string, roles []signature.SignerRole) error {
	_, err := GenerateDeterministicNodeKeys(dir, rawSeed, roles)
	return err
}

func (net *Network) generateDeterministicNodeIdentity(dir *env.Dir, rawSeed string) error {
	return net.generateDeterministicIdentity(dir, rawSeed, identity.RequiredSignerRoles)
}

// GenerateDeterministicNodeKeys generates and returns deterministic node keys.
func GenerateDeterministicNodeKeys(dir *env.Dir, rawSeed string, roles []signature.SignerRole) ([]signature.PublicKey, error) {
	h := crypto.SHA512.New()
	_, _ = h.Write([]byte(rawSeed))
	seed := h.Sum(nil)

	rng, err := drbg.New(crypto.SHA512, seed, nil, []byte("deterministic node identities test"))
	if err != nil {
		return nil, err
	}

	var dirStr string
	factoryCtor := func(args interface{}, roles ...signature.SignerRole) (signature.SignerFactory, error) {
		return memorySigner.NewFactory(), nil
	}
	if dir != nil {
		factoryCtor = fileSigner.NewFactory
		dirStr = dir.String()
	}

	var pks []signature.PublicKey
	for _, role := range roles {
		factory, err := factoryCtor(dirStr, role)
		if err != nil {
			return nil, err
		}
		signer, err := factory.Generate(role, rng)
		if err != nil {
			return nil, err
		}
		pks = append(pks, signer.Public())
	}

	return pks, nil
}

// generateTempSocketPath returns a unique filename for a node's internal socket in the test base dir
//
// This function is used to obtain shorter socket path than the one in datadir since that one might
// be too long for unix socket path.
func (net *Network) generateTempSocketPath(prefix string) string {
	f, err := ioutil.TempFile(env.GetRootDir().String(), fmt.Sprintf("%s-internal-*.sock", prefix))
	if err != nil {
		return ""
	}
	defer f.Close()
	return f.Name()
}

func (net *Network) startOasisNode(
	node *Node,
	subCmd []string,
	extraArgs *argBuilder,
) error {
	node.Lock()
	defer node.Unlock()

	// Make a deep copy as we will be modifying the arguments.
	initialExtraArgs := extraArgs.clone()

	baseArgs := []string{
		"--" + cmdCommon.CfgDataDir, node.dir.String(),
		"--log.level", "debug",
		"--log.format", "json",
		"--log.file", nodeLogPath(node.dir),
		"--genesis.file", net.GenesisPath(),
	}
	if len(subCmd) == 0 {
		extraArgs = extraArgs.
			debugAllowDebugEnclaves().
			appendIASProxy(net.iasProxy).
			tendermintDebugAddrBookLenient().
			tendermintDebugAllowDuplicateIP().
			tendermintUpgradeStopDelay(10 * time.Second)
	}
	if net.cfg.UseShortGrpcSocketPaths {
		// Keep the socket, if it was already generated!
		if node.customGrpcSocketPath == "" {
			node.customGrpcSocketPath = net.generateTempSocketPath(node.Name)
		}
		extraArgs = extraArgs.debugDontBlameOasis()
		extraArgs = extraArgs.grpcDebugGrpcInternalSocketPath(node.customGrpcSocketPath)
	}
	if node.consensusStateSync != nil {
		extraArgs = extraArgs.tendermintStateSync(
			node.consensusStateSync.ConsensusNodes,
			node.consensusStateSync.TrustHeight,
			node.consensusStateSync.TrustHash,
		)
	}
	if viper.IsSet(metrics.CfgMetricsAddr) {
		extraArgs = extraArgs.appendNodeMetrics(node)
	}
	args := append([]string{}, subCmd...)
	args = append(args, baseArgs...)
	args = append(args, extraArgs.merge(node.dir.String())...)

	w, err := node.dir.NewLogWriter(logConsoleFile)
	if err != nil {
		return err
	}
	net.env.AddOnCleanup(func() {
		_ = w.Close()
	})

	oasisBinary := net.cfg.NodeBinary
	cmd := exec.Command(oasisBinary, args...)
	cmd.SysProcAttr = env.CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	net.logger.Info("launching Oasis node",
		"args", strings.Join(args, " "),
	)

	if err = cmd.Start(); err != nil {
		return fmt.Errorf("oasis: failed to start node: %w", err)
	}

	doneCh := net.env.AddTermOnCleanup(cmd)
	exitCh := make(chan error, 1)
	go func() {
		defer close(exitCh)

		cmdErr := <-doneCh
		net.logger.Debug("node terminated",
			"err", cmdErr,
		)

		if cmdErr != nil {
			exitCh <- cmdErr
		}

		if err := node.handleExit(cmdErr); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && exitErr.ExitCode() == crash.CrashDefaultExitCode {
				// Termination due to crasher. Restart node.
				net.logger.Info("Node debug crash point triggered. Restarting...", "node", node.Name)
				if err = net.startOasisNode(node, subCmd, initialExtraArgs); err != nil {
					net.errCh <- fmt.Errorf("oasis: %s failed restarting node after crash point: %w", node.Name, err)
				}
				return
			}

			net.errCh <- fmt.Errorf("oasis: %s node terminated: %w", node.Name, err)
		}
	}()

	node.cmd = cmd
	node.exitCh = exitCh

	return nil
}

// MakeGenesis generates a new Genesis file.
func (net *Network) MakeGenesis() error {
	args := []string{
		"genesis", "init",
		"--genesis.file", net.GenesisPath(),
		"--chain.id", genesisTestHelpers.TestChainID,
		"--initial_height", strconv.FormatInt(net.cfg.InitialHeight, 10),
		"--halt.epoch", strconv.FormatUint(net.cfg.HaltEpoch, 10),
		"--consensus.backend", net.cfg.Consensus.Backend,
		"--consensus.tendermint.timeout_commit", net.cfg.Consensus.Parameters.TimeoutCommit.String(),
		"--registry.enable_runtime_governance_models", "entity,runtime",
		"--registry.debug.allow_unroutable_addresses", "true",
		"--" + genesis.CfgRegistryDebugAllowTestRuntimes, "true",
		"--scheduler.max_validators_per_entity", strconv.Itoa(len(net.Validators())),
		"--" + genesis.CfgConsensusGasCostsTxByte, strconv.FormatUint(uint64(net.cfg.Consensus.Parameters.GasCosts[consensusGenesis.GasOpTxByte]), 10),
		"--" + genesis.CfgConsensusStateCheckpointInterval, strconv.FormatUint(net.cfg.Consensus.Parameters.StateCheckpointInterval, 10),
		"--" + genesis.CfgConsensusStateCheckpointNumKept, strconv.FormatUint(net.cfg.Consensus.Parameters.StateCheckpointNumKept, 10),
		"--" + genesis.CfgStakingTokenSymbol, genesisTestHelpers.TestStakingTokenSymbol,
		"--" + genesis.CfgStakingTokenValueExponent, strconv.FormatUint(
			uint64(genesisTestHelpers.TestStakingTokenValueExponent), 10),
		"--" + genesis.CfgBeaconBackend, net.cfg.Beacon.Backend,
	}
	switch net.cfg.Beacon.Backend {
	case beacon.BackendInsecure:
		args = append(args, []string{
			"--" + genesis.CfgBeaconInsecureTendermintInterval, strconv.FormatInt(net.cfg.Beacon.InsecureParameters.Interval, 10),
		}...)
	case beacon.BackendVRF:
		args = append(args, []string{
			"--" + genesis.CfgBeaconVRFAlphaThreshold, strconv.FormatUint(net.cfg.Beacon.VRFParameters.AlphaHighQualityThreshold, 10),
			"--" + genesis.CfgBeaconVRFInterval, strconv.FormatUint(uint64(net.cfg.Beacon.VRFParameters.Interval), 10),
			"--" + genesis.CfgBeaconVRFProofSubmissionDelay, strconv.FormatUint(uint64(net.cfg.Beacon.VRFParameters.ProofSubmissionDelay), 10),
		}...)
		if net.cfg.SchedulerWeakAlphaOk {
			args = append(args, []string{
				"--" + genesis.CfgSchedulerDebugAllowWeakAlpha, "true",
			}...)
		}
	default:
		return fmt.Errorf("oasis: unsupported beacon backend: %s", net.cfg.Beacon.Backend)
	}
	if net.cfg.Beacon.DebugMockBackend {
		args = append(args, "--"+genesis.CfgBeaconDebugMockBackend)
	}
	if cfg := net.cfg.GovernanceParameters; cfg != nil {
		args = append(args, []string{
			"--" + genesis.CfgGovernanceMinProposalDeposit, strconv.FormatUint(cfg.MinProposalDeposit.ToBigInt().Uint64(), 10),
			"--" + genesis.CfgGovernanceStakeThreshold, strconv.FormatUint(uint64(cfg.StakeThreshold), 10),
			"--" + genesis.CfgGovernanceUpgradeCancelMinEpochDiff, strconv.FormatUint(uint64(cfg.UpgradeCancelMinEpochDiff), 10),
			"--" + genesis.CfgGovernanceUpgradeMinEpochDiff, strconv.FormatUint(uint64(cfg.UpgradeMinEpochDiff), 10),
			"--" + genesis.CfgGovernanceVotingPeriod, strconv.FormatUint(uint64(cfg.VotingPeriod), 10),
			"--" + genesis.CfgGovernanceEnableChangeParametersProposal, strconv.FormatBool(cfg.EnableChangeParametersProposal),
		}...)
	}
	if cfg := net.cfg.RoothashParameters; cfg != nil {
		args = append(args, []string{
			"--" + genesis.CfgRoothashMaxRuntimeMessages, strconv.FormatUint(uint64(cfg.MaxRuntimeMessages), 10),
			"--" + genesis.CfgRoothashMaxInRuntimeMessages, strconv.FormatUint(uint64(cfg.MaxInRuntimeMessages), 10),
		}...)
	}
	if cfg := net.cfg.SchedulerForceElect; cfg != nil {
		data, err := json.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("oasis: failed to marshal scheduler force elect config: %w", err)
		}

		args = append(args, []string{
			"--" + genesis.CfgSchedulerDebugForceElect,
			string(data),
		}...)
	}
	for _, v := range net.entities {
		args = append(args, v.toGenesisDescriptorArgs()...)
	}
	for _, v := range net.validators {
		args = append(args, v.toGenesisArgs()...)
	}
	for _, v := range net.runtimes {
		args = append(args, v.toGenesisArgs()...)
	}
	for _, v := range net.keymanagerPolicies {
		if err := v.provision(); err != nil {
			return err
		}
	}
	for _, v := range net.keymanagers {
		if err := v.provisionGenesis(); err != nil {
			return err
		}
		args = append(args, v.toGenesisArgs()...)
	}

	if net.cfg.StakingGenesis != nil {
		if net.cfg.FundEntities {
			toFund := quantity.NewFromUint64(1000000000000)
			if net.cfg.StakingGenesis.Ledger == nil {
				net.cfg.StakingGenesis.Ledger = make(map[staking.Address]*staking.Account)
			}
			for _, ent := range net.Entities() {
				if ent.isDebugTestEntity {
					// Debug test entities already get funded.
					continue
				}
				net.cfg.StakingGenesis.Ledger[staking.NewAddress(ent.Signer().Public())] = &staking.Account{
					General: staking.GeneralAccount{
						Balance: *toFund,
					},
				}
				_ = net.cfg.StakingGenesis.TotalSupply.Add(toFund)
			}
		}

		path := filepath.Join(net.baseDir.String(), stakingGenesisFile)
		b, err := json.Marshal(net.cfg.StakingGenesis)
		if err != nil {
			net.logger.Error("failed to serialize staking genesis file",
				"err", err,
			)
			return fmt.Errorf("oasis: failed to serialize staking genesis file: %w", err)
		}
		if err = ioutil.WriteFile(path, b, 0o600); err != nil {
			net.logger.Error("failed to write staking genesis file",
				"err", err,
			)
			return fmt.Errorf("oasis: failed to write staking genesis file: %w", err)
		}
		args = append(args, "--staking", path)
	}
	if len(net.byzantine) > 0 {
		// If the byzantine node is in use, disable max node expiration
		// enforcement, because it wants to register for 1000 epochs.
		args = append(args, []string{
			"--" + genesis.CfgRegistryMaxNodeExpiration, "0",
		}...)
	}

	w, err := net.baseDir.NewLogWriter("genesis_provision.log")
	if err != nil {
		return err
	}
	defer w.Close()

	if err := net.runNodeBinary(w, args...); err != nil {
		net.logger.Error("failed to create genesis file",
			"err", err,
		)
		return fmt.Errorf("oasis: failed to create genesis file: %w", err)
	}

	return nil
}

// GenesisPath returns the path to the genesis file for the network.
func (net *Network) GenesisPath() string {
	if net.cfg.GenesisFile != "" {
		return net.cfg.GenesisFile
	}
	return filepath.Join(net.baseDir.String(), "genesis.json")
}

// BasePath returns the path to the network base directory.
func (net *Network) BasePath() string {
	return net.baseDir.String()
}

// GetCLIConfig implements cli.Factory.
func (net *Network) GetCLIConfig() cli.Config {
	cfg := cli.Config{
		NodeBinary:  net.cfg.NodeBinary,
		GenesisFile: net.GenesisPath(),
	}
	if len(net.Validators()) > 0 {
		val := net.Validators()[0]
		if net.cfg.UseShortGrpcSocketPaths && val.customGrpcSocketPath == "" {
			val.customGrpcSocketPath = net.generateTempSocketPath(val.Node.Name)
		}
		cfg.NodeSocketPath = val.SocketPath()
	}
	return cfg
}

func (net *Network) provisionNodeIdentity(dataDir *env.Dir, seed string, persistTLS bool) (signature.PublicKey, signature.PublicKey, *x509.Certificate, error) {
	if net.cfg.DeterministicIdentities && !net.cfg.RestoreIdentities {
		if err := net.generateDeterministicNodeIdentity(dataDir, seed); err != nil {
			return signature.PublicKey{}, signature.PublicKey{}, nil, fmt.Errorf("oasis: failed to generate deterministic identity: %w", err)
		}
	}

	signerFactory, err := fileSigner.NewFactory(dataDir.String(), identity.RequiredSignerRoles...)
	if err != nil {
		return signature.PublicKey{}, signature.PublicKey{}, nil, fmt.Errorf("oasis: failed to create node file signer factory: %w", err)
	}
	nodeIdentity, err := identity.LoadOrGenerate(dataDir.String(), signerFactory, persistTLS)
	if err != nil {
		return signature.PublicKey{}, signature.PublicKey{}, nil, fmt.Errorf("oasis: failed to provision node identity: %w", err)
	}
	sentryCert, err := x509.ParseCertificate(nodeIdentity.TLSSentryClientCertificate.Certificate[0])
	if err != nil {
		return signature.PublicKey{}, signature.PublicKey{}, nil, fmt.Errorf("oasis: failed to parse sentry client certificate: %w", err)
	}
	return nodeIdentity.NodeSigner.Public(), nodeIdentity.P2PSigner.Public(), sentryCert, nil
}

// New creates a new test Oasis network.
func New(env *env.Env, cfg *NetworkCfg) (*Network, error) {
	baseDir, err := env.NewSubDir("network")
	if err != nil {
		return nil, fmt.Errorf("oasis: failed to create network sub-directory: %w", err)
	}

	// Copy the config and apply some sane defaults.
	cfgCopy := *cfg
	if cfgCopy.Consensus.Backend == "" {
		cfgCopy.Consensus.Backend = defaultConsensusBackend
	}
	if cfgCopy.Consensus.Parameters.TimeoutCommit == 0 {
		cfgCopy.Consensus.Parameters.TimeoutCommit = defaultConsensusTimeoutCommit
	}
	if cfgCopy.Consensus.Parameters.GasCosts == nil {
		cfgCopy.Consensus.Parameters.GasCosts = make(transaction.Costs)
	}
	if cfgCopy.Beacon.Backend == "" {
		cfgCopy.Beacon.Backend = beacon.BackendVRF
	}
	switch cfgCopy.Beacon.Backend {
	case beacon.BackendInsecure:
		if cfgCopy.Beacon.InsecureParameters == nil {
			cfgCopy.Beacon.InsecureParameters = new(beacon.InsecureParameters)
		}
		if cfgCopy.Beacon.InsecureParameters.Interval == 0 {
			cfgCopy.Beacon.InsecureParameters.Interval = defaultEpochtimeTendermintInterval
		}
	case beacon.BackendVRF:
		if cfgCopy.Beacon.VRFParameters == nil {
			cfgCopy.Beacon.VRFParameters = new(beacon.VRFParameters)
		}
		if cfgCopy.Beacon.VRFParameters.AlphaHighQualityThreshold == 0 {
			cfgCopy.Beacon.VRFParameters.AlphaHighQualityThreshold = defaultVRFAlphaThreshold
		}
		if cfgCopy.Beacon.VRFParameters.Interval == 0 {
			cfgCopy.Beacon.VRFParameters.Interval = defaultVRFInterval
		}
		if cfgCopy.Beacon.VRFParameters.ProofSubmissionDelay == 0 {
			cfgCopy.Beacon.VRFParameters.ProofSubmissionDelay = defaultVRFSubmissionDelay
		}
	}
	if cfgCopy.InitialHeight == 0 {
		cfgCopy.InitialHeight = defaultInitialHeight
	}
	if cfgCopy.HaltEpoch == 0 {
		cfgCopy.HaltEpoch = defaultHaltEpoch
	}

	net := &Network{
		logger:       logging.GetLogger("oasis/" + env.Name()),
		env:          env,
		baseDir:      baseDir,
		cfg:          &cfgCopy,
		nextNodePort: baseNodePort,
		errCh:        make(chan error, maxNodes),
	}

	// Pre-provision node objects if they were listed in the top-level network fixture.
	for _, nodeName := range cfg.Nodes {
		_, err = net.GetNamedNode(nodeName, nil)
		if err != nil {
			return nil, fmt.Errorf("oasis: failed to create node %s: %w", nodeName, err)
		}
	}

	return net, nil
}
