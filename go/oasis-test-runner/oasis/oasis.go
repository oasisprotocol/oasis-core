// Package oasis provides the Oasis network/node/client related test helpers.
package oasis

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/genesis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	baseNodePort = 20000

	validatorStartDelay = 3 * time.Second

	defaultConsensusBackend            = "tendermint"
	defaultConsensusTimeoutCommit      = 250 * time.Millisecond
	defaultEpochtimeTendermintInterval = 30
	defaultInitialHeight               = 1
	defaultHaltEpoch                   = math.MaxUint64

	logNodeFile        = "node.log"
	logConsoleFile     = "console.log"
	exportsDir         = "exports"
	stakingGenesisFile = "staking_genesis.json"

	maxNodes = 32 // Arbitrary
)

// ConsensusStateSyncCfg is a node's consensus state sync configuration.
type ConsensusStateSyncCfg struct {
	ConsensusNodes []string
	TrustHeight    uint64
	TrustHash      string
}

// Node defines the common fields for all node types.
type Node struct { // nolint: maligned
	sync.Mutex

	Name   string
	NodeID signature.PublicKey

	net *Network
	dir *env.Dir
	cmd *exec.Cmd

	exitCh chan error

	termEarlyOk bool
	termErrorOk bool
	doStartNode func() error
	isStopping  bool
	noAutoStart bool

	crashPointsProbability float64

	disableDefaultLogWatcherHandlerFactories bool
	logWatcherHandlerFactories               []log.WatcherHandlerFactory

	consensus            ConsensusFixture
	consensusStateSync   *ConsensusStateSyncCfg
	customGrpcSocketPath string
}

// Exit returns a channel that will close once the node shuts down.
// If the node shut down due to an error, that error will be sent through this channel.
func (n *Node) Exit() chan error {
	return n.exitCh
}

// SocketPath returns the path of the node's gRPC unix socket.
func (n *Node) SocketPath() string {
	// Return custom (shorter?) socket path, if set.
	if n.customGrpcSocketPath != "" {
		return n.customGrpcSocketPath
	}

	return internalSocketPath(n.dir)
}

// LogPath returns the path to the node's log.
func (n *Node) LogPath() string {
	return nodeLogPath(n.dir)
}

// DataDir returns the path to the node's data directory.
func (n *Node) DataDir() string {
	return n.dir.String()
}

// LoadIdentity loads the node's identity.
func (n *Node) LoadIdentity() (*identity.Identity, error) {
	factory, err := fileSigner.NewFactory(n.dir.String(), signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	if err != nil {
		return nil, err
	}
	return identity.Load(n.dir.String(), factory)
}

func (n *Node) stopNode() error {
	if n.cmd == nil {
		return nil
	}

	// Mark the node as stopping so that we don't abort the scenario when the node exits.
	n.Lock()
	n.isStopping = true
	n.Unlock()

	// Stop the node and wait for it to stop.
	_ = n.cmd.Process.Kill()
	_ = n.cmd.Wait()
	<-n.Exit()
	n.cmd = nil

	return nil
}

// Stop stops the node.
func (n *Node) Stop() error {
	return n.stopNode()
}

// Restart kills the node, waits for it to stop, and starts it again.
func (n *Node) Restart(ctx context.Context) error {
	return n.RestartAfter(ctx, 0)
}

// RestartAfter kills the node, waits for it to stop, and starts it again after delay.
func (n *Node) RestartAfter(ctx context.Context, startDelay time.Duration) error {
	if err := n.stopNode(); err != nil {
		return err
	}
	select {
	case <-time.After(startDelay):
	case <-ctx.Done():
		return ctx.Err()
	}
	return n.doStartNode()
}

// BinaryPath returns the path to the running node's process' image, or an empty string
// if the node isn't running yet. This can be used as a replacement for NetworkCfg.NodeBinary
// in cases where the test runner is actually using a wrapper to start the node.
func (n *Node) BinaryPath() string {
	if n.cmd == nil || n.cmd.Process == nil {
		return ""
	}

	return fmt.Sprintf("/proc/%d/exe", n.cmd.Process.Pid)
}

// WaitReady is a helper for creating a controller and calling node's WaitReady.
func (n *Node) WaitReady(ctx context.Context) error {
	nodeCtrl, err := NewController(n.SocketPath())
	if err != nil {
		return err
	}
	return nodeCtrl.WaitReady(ctx)
}

// RequestShutdown is a helper for creating a controller and calling node's RequestShutdown.
func (n *Node) RequestShutdown(ctx context.Context, wait bool) error {
	nodeCtrl, err := NewController(n.SocketPath())
	if err != nil {
		return err
	}
	return nodeCtrl.RequestShutdown(ctx, wait)
}

func (n *Node) handleExit(cmdErr error) error {
	n.Lock()
	defer n.Unlock()

	switch {
	case n.termErrorOk || n.isStopping:
		// Termination with any error code is allowed.
		n.isStopping = false
		return nil
	case cmdErr == env.ErrEarlyTerm && n.termEarlyOk:
		// Early (successful) termination is allowed.
		return nil
	default:
		return cmdErr
	}
}

// Consensus returns the node's consensus configuration.
func (n *Node) Consensus() ConsensusFixture {
	return n.consensus
}

// SetConsensusStateSync configures whether a node should perform consensus
// state sync.
func (n *Node) SetConsensusStateSync(cfg *ConsensusStateSyncCfg) {
	n.Lock()
	defer n.Unlock()

	n.consensusStateSync = cfg
}

// NodeCfg defines the common node configuration options.
type NodeCfg struct { // nolint: maligned
	AllowEarlyTermination  bool
	AllowErrorTermination  bool
	CrashPointsProbability float64

	NoAutoStart bool

	DisableDefaultLogWatcherHandlerFactories bool
	LogWatcherHandlerFactories               []log.WatcherHandlerFactory

	// Consensus contains configuration for the consensus backend.
	Consensus ConsensusFixture
}

// Network is a test Oasis network.
type Network struct { // nolint: maligned
	logger *logging.Logger

	env     *env.Env
	baseDir *env.Dir
	running bool

	entities       []*Entity
	validators     []*Validator
	runtimes       []*Runtime
	keymanagers    []*Keymanager
	storageWorkers []*Storage
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
	// UseRegistry specifies whether the IAS proxy should use the registry
	// instead of the genesis document for authenticating runtime IDs.
	UseRegistry bool `json:"use_registry,omitempty"`

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

	// EpochtimeMock is the mock epochtime flag.
	EpochtimeMock bool `json:"epochtime_mock"`

	// EpochtimeTendermintInterval is the tendermint epochtime block interval.
	EpochtimeTendermintInterval int64 `json:"epochtime_tendermint_interval"`

	// DeterministicIdentities is the deterministic identities flag.
	DeterministicIdentities bool `json:"deterministic_identities"`

	// FundEntities is the fund entities flag.
	FundEntities bool `json:"fund_entities"`

	// IAS is the Network IAS configuration.
	IAS IASCfg `json:"ias"`

	// StakingGenesis is the staking genesis data to be included if
	// GenesisFile is not set.
	StakingGenesis *staking.Genesis `json:"staking_genesis,omitempty"`

	// GovernanceParameters are the governance consensus parameters.
	GovernanceParameters *governance.ConsensusParameters `json:"governance_parameters,omitempty"`

	// A set of log watcher handler factories used by default on all nodes
	// created in this test network.
	DefaultLogWatcherHandlerFactories []log.WatcherHandlerFactory `json:"-"`

	// UseShortGrpcSocketPaths specifies whether nodes should use internal.sock in datadir or
	// externally-provided.
	UseShortGrpcSocketPaths bool `json:"-"`
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

// StorageWorkers returns the storage worker nodes associated with the network.
func (net *Network) StorageWorkers() []*Storage {
	return net.storageWorkers
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
// Seed, sentry, byzantine and IAS proxy nodes are omitted.
func (net *Network) Nodes() []*Node {
	var nodes []*Node
	for _, v := range net.Validators() {
		nodes = append(nodes, &v.Node)
	}
	for _, s := range net.StorageWorkers() {
		nodes = append(nodes, &s.Node)
	}
	for _, c := range net.ComputeWorkers() {
		nodes = append(nodes, &c.Node)
	}
	for _, k := range net.Keymanagers() {
		nodes = append(nodes, &k.Node)
	}
	for _, v := range net.Clients() {
		nodes = append(nodes, &v.Node)
	}
	return nodes
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

// NumRegisterNodes returns the number of all nodes that need to register.
func (net *Network) NumRegisterNodes() int {
	return len(net.validators) +
		len(net.keymanagers) +
		len(net.storageWorkers) +
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

	net.logger.Debug("starting IAS proxy node")
	if net.iasProxy != nil {
		if err = net.iasProxy.startNode(); err != nil {
			net.logger.Error("failed to start IAS proxy node",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting seed node(s)")
	for _, s := range net.seeds {
		if s.noAutoStart {
			continue
		}

		if err = s.startNode(); err != nil {
			net.logger.Error("failed to start seed node",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting validator node(s)")
	for _, v := range net.validators {
		if v.noAutoStart {
			continue
		}

		if err = v.startNode(); err != nil {
			net.logger.Error("failed to start validator",
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
		time.Sleep(validatorStartDelay)
	}

	net.logger.Debug("starting keymanager(s)")
	for _, km := range net.keymanagers {
		if km.noAutoStart {
			continue
		}

		if err = km.startNode(); err != nil {
			net.logger.Error("failed to start keymanager node",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting storage node(s)")
	for _, v := range net.storageWorkers {
		if v.noAutoStart {
			continue
		}

		if err = v.startNode(); err != nil {
			net.logger.Error("failed to start storage worker",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting compute node(s)")
	for _, v := range net.computeWorkers {
		if v.noAutoStart {
			continue
		}

		if err = v.startNode(); err != nil {
			net.logger.Error("failed to start compute worker",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting sentry node(s)")
	for _, v := range net.sentries {
		if v.noAutoStart {
			continue
		}

		if err = v.startNode(); err != nil {
			net.logger.Error("failed to start sentry node",
				"err", err,
			)
			return err
		}

	}

	net.logger.Debug("starting client node(s)")
	for _, v := range net.clients {
		if v.noAutoStart {
			continue
		}

		if err = v.startNode(); err != nil {
			net.logger.Error("failed to start client node",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting byzantine node(s)")
	for _, v := range net.byzantine {
		if v.noAutoStart {
			continue
		}

		if err = v.startNode(); err != nil {
			net.logger.Error("failed to start byzantine node",
				"err", err,
			)
			return err
		}
	}

	// Use the first started validator as a controller.
	for _, v := range net.validators {
		if v.noAutoStart {
			continue
		}

		if net.controller, err = NewController(net.validators[0].SocketPath()); err != nil {
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

		if net.clientController, err = NewController(net.clients[0].SocketPath()); err != nil {
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
	h := crypto.SHA512.New()
	_, _ = h.Write([]byte(rawSeed))
	seed := h.Sum(nil)

	rng, err := drbg.New(crypto.SHA512, seed, nil, []byte("deterministic node identities test"))
	if err != nil {
		return err
	}

	for _, role := range roles {
		factory, err := fileSigner.NewFactory(dir.String(), role)
		if err != nil {
			return err
		}
		if _, err = factory.Generate(role, rng); err != nil {
			return err
		}
	}

	return nil
}

func (net *Network) generateDeterministicNodeIdentity(dir *env.Dir, rawSeed string) error {
	return net.generateDeterministicIdentity(dir, rawSeed, []signature.SignerRole{
		signature.SignerNode,
		signature.SignerP2P,
		signature.SignerConsensus,
	})
}

// generateTempSocketPath returns a unique filename for a node's internal socket in the test base dir
//
// This function is used to obtain shorter socket path than the one in datadir since that one might
// be too long for unix socket path.
func (net *Network) generateTempSocketPath() string {
	f, err := ioutil.TempFile(env.GetRootDir().String(), "internal-*.sock")
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

	baseArgs := []string{
		"--" + common.CfgDataDir, node.dir.String(),
		"--log.level", "debug",
		"--log.format", "json",
		"--log.file", nodeLogPath(node.dir),
		"--genesis.file", net.GenesisPath(),
	}
	if len(subCmd) == 0 {
		extraArgs = extraArgs.
			appendIASProxy(net.iasProxy).
			tendermintDebugAddrBookLenient().
			tendermintDebugAllowDuplicateIP()
	}
	if net.cfg.UseShortGrpcSocketPaths {
		// Keep the socket, if it was already generated!
		if node.customGrpcSocketPath == "" {
			node.customGrpcSocketPath = net.generateTempSocketPath()
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
	args = append(args, extraArgs.vec...)

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
				if err = net.startOasisNode(node, subCmd, extraArgs); err != nil {
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
		"--epochtime.tendermint.interval", strconv.FormatInt(net.cfg.EpochtimeTendermintInterval, 10),
		"--consensus.tendermint.timeout_commit", net.cfg.Consensus.Parameters.TimeoutCommit.String(),
		"--registry.debug.allow_unroutable_addresses", "true",
		"--" + genesis.CfgRegistryDebugAllowTestRuntimes, "true",
		"--scheduler.max_validators_per_entity", strconv.Itoa(len(net.Validators())),
		"--" + genesis.CfgConsensusGasCostsTxByte, strconv.FormatUint(uint64(net.cfg.Consensus.Parameters.GasCosts[consensusGenesis.GasOpTxByte]), 10),
		"--" + genesis.CfgConsensusStateCheckpointInterval, strconv.FormatUint(net.cfg.Consensus.Parameters.StateCheckpointInterval, 10),
		"--" + genesis.CfgConsensusStateCheckpointNumKept, strconv.FormatUint(net.cfg.Consensus.Parameters.StateCheckpointNumKept, 10),
		"--" + genesis.CfgStakingTokenSymbol, genesisTestHelpers.TestStakingTokenSymbol,
		"--" + genesis.CfgStakingTokenValueExponent, strconv.FormatUint(
			uint64(genesisTestHelpers.TestStakingTokenValueExponent), 10),
	}
	if net.cfg.EpochtimeMock {
		args = append(args, "--epochtime.debug.mock_backend")
	}
	if net.cfg.DeterministicIdentities {
		args = append(args, "--beacon.debug.deterministic")
	}
	if cfg := net.cfg.GovernanceParameters; cfg != nil {
		args = append(args, []string{
			"--" + genesis.CfgGovernanceMinProposalDeposit, strconv.FormatUint(cfg.MinProposalDeposit.ToBigInt().Uint64(), 10),
			"--" + genesis.CfgGovernanceQuorum, strconv.FormatUint(uint64(cfg.Quorum), 10),
			"--" + genesis.CfgGovernanceThreshold, strconv.FormatUint(uint64(cfg.Threshold), 10),
			"--" + genesis.CfgGovernanceUpgradeCancelMinEpochDiff, strconv.FormatUint(uint64(cfg.UpgradeCancelMinEpochDiff), 10),
			"--" + genesis.CfgGovernanceUpgradeMinEpochDiff, strconv.FormatUint(uint64(cfg.UpgradeMinEpochDiff), 10),
			"--" + genesis.CfgGovernanceVotingPeriod, strconv.FormatUint(uint64(cfg.VotingPeriod), 10),
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

// Implements cli.Factory.
func (net *Network) GetCLIConfig() cli.Config {
	cfg := cli.Config{
		NodeBinary:  net.cfg.NodeBinary,
		GenesisFile: net.GenesisPath(),
	}
	if len(net.Validators()) > 0 {
		val := net.Validators()[0]
		if net.cfg.UseShortGrpcSocketPaths && val.customGrpcSocketPath == "" {
			val.customGrpcSocketPath = net.generateTempSocketPath()
		}
		cfg.NodeSocketPath = val.SocketPath()
	}
	return cfg
}

func (net *Network) provisionNodeIdentity(dataDir *env.Dir, seed string, persistTLS bool) (signature.PublicKey, signature.PublicKey, *x509.Certificate, error) {
	if net.cfg.DeterministicIdentities {
		if err := net.generateDeterministicNodeIdentity(dataDir, seed); err != nil {
			return signature.PublicKey{}, signature.PublicKey{}, nil, fmt.Errorf("oasis: failed to generate deterministic identity: %w", err)
		}
	}

	signerFactory, err := fileSigner.NewFactory(dataDir.String(), signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
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
	if cfgCopy.EpochtimeTendermintInterval == 0 {
		cfgCopy.EpochtimeTendermintInterval = defaultEpochtimeTendermintInterval
	}
	if cfgCopy.InitialHeight == 0 {
		cfgCopy.InitialHeight = defaultInitialHeight
	}
	if cfgCopy.HaltEpoch == 0 {
		cfgCopy.HaltEpoch = defaultHaltEpoch
	}

	return &Network{
		logger:       logging.GetLogger("oasis/" + env.Name()),
		env:          env,
		baseDir:      baseDir,
		cfg:          &cfgCopy,
		nextNodePort: baseNodePort,
		errCh:        make(chan error, maxNodes),
	}, nil
}

func nodeLogPath(dir *env.Dir) string {
	return filepath.Join(dir.String(), logNodeFile)
}

func internalSocketPath(dir *env.Dir) string {
	return filepath.Join(dir.String(), grpc.LocalSocketFilename)
}

func nodeIdentityKeyPath(dir *env.Dir) string {
	return filepath.Join(dir.String(), fileSigner.FileIdentityKey)
}

func nodeP2PKeyPath(dir *env.Dir) string {
	return filepath.Join(dir.String(), fileSigner.FileP2PKey)
}

func nodeConsensusKeyPath(dir *env.Dir) string {
	return filepath.Join(dir.String(), fileSigner.FileConsensusKey)
}

func nodeTLSKeyPath(dir *env.Dir) string {
	_, path := identity.TLSCertPaths(dir.String())
	return path
}

func nodeTLSCertPath(dir *env.Dir) string {
	path, _ := identity.TLSCertPaths(dir.String())
	return path
}

func nodeExportsPath(dir *env.Dir) string {
	return filepath.Join(dir.String(), exportsDir)
}
