// Package oasis provides the Oasis network/node/client related test helpers.
package oasis

import (
	"crypto"
	"fmt"
	"io"
	"math"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/crypto/drbg"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	genesisFile "github.com/oasislabs/oasis-core/go/genesis/file"
	genesisTestHelpers "github.com/oasislabs/oasis-core/go/genesis/tests"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/genesis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/log"
)

const (
	baseNodePort = 20000

	validatorStartDelay = 3 * time.Second

	defaultConsensusBackend            = "tendermint"
	defaultConsensusTimeoutCommit      = 250 * time.Millisecond
	defaultEpochtimeTendermintInterval = 30
	defaultHaltEpoch                   = math.MaxUint64

	internalSocketFile = "internal.sock"

	logNodeFile    = "node.log"
	logConsoleFile = "console.log"
	exportsDir     = "exports"

	maxNodes = 32 // Arbitrary
)

// Node defines the common fields for all node types.
type Node struct { // nolint: maligned
	Name   string
	NodeID signature.PublicKey

	net *Network
	dir *env.Dir
	cmd *exec.Cmd

	exitCh chan error

	restartable bool
	doStartNode func() error

	disableDefaultLogWatcherHandlerFactories bool
	logWatcherHandlerFactories               []log.WatcherHandlerFactory

	submissionGasPrice uint64
}

// Exit returns a channel that will close once the node shuts down.
// If the node shut down due to an error, that error will be sent through this channel.
func (n *Node) Exit() chan error {
	return n.exitCh
}

// SocketPath returns the path to the node's gRPC socket.
func (n *Node) SocketPath() string {
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

func (n *Node) stopNode() error {
	if n.cmd == nil {
		return nil
	}

	// Stop the node and wait for it to stop.
	_ = n.cmd.Process.Kill()
	_ = n.cmd.Wait()
	n.cmd = nil
	return nil
}

// Stop stops the node.
func (n *Node) Stop() error {
	return n.stopNode()
}

// Restart kills the node, waits for it to stop, and starts it again.
func (n *Node) Restart() error {
	if err := n.stopNode(); err != nil {
		return err
	}
	return n.doStartNode()
}

// BinaryPath returns the path to the running node's process' image, or an empty string
// if the node isn't running yet. This can be used as a replacement for NetworkCfg.NodeBinary
// in cases where the test runner is actually using a wrapper to start the node.
func (n Node) BinaryPath() string {
	if n.cmd == nil || n.cmd.Process == nil {
		return ""
	}

	return fmt.Sprintf("/proc/%d/exe", n.cmd.Process.Pid)
}

// NodeCfg defines the common node configuration options.
type NodeCfg struct {
	Restartable bool

	DisableDefaultLogWatcherHandlerFactories bool
	LogWatcherHandlerFactories               []log.WatcherHandlerFactory

	SubmissionGasPrice uint64
}

// CmdAttrs is the SysProcAttr that will ensure graceful cleanup.
var CmdAttrs = &syscall.SysProcAttr{
	Pdeathsig: syscall.SIGKILL,
}

// Network is a test Oasis network.
type Network struct {
	logger *logging.Logger

	env     *env.Env
	baseDir *env.Dir

	entities       []*Entity
	validators     []*Validator
	runtimes       []*Runtime
	keymanagers    []*Keymanager
	storageWorkers []*Storage
	computeWorkers []*Compute
	sentries       []*Sentry
	clients        []*Client
	byzantine      []*Byzantine

	seedNode *seedNode
	iasProxy *iasProxy

	cfg          *NetworkCfg
	nextNodePort uint16

	logWatchers []*log.Watcher

	controller       *Controller
	clientController *Controller

	errCh chan error
}

// NetworkCfg is the Oasis test network configuration.
type NetworkCfg struct { // nolint: maligned
	// GenesisFile is an optional genesis file to use.
	GenesisFile string `json:"genesis_file,omitempty"`

	// NodeBinary is the path to the Oasis node binary.
	NodeBinary string `json:"node_binary"`

	// RuntimeLoaderBinary is the path to the Oasis runtime loader.
	RuntimeLoaderBinary string `json:"runtime_loader_binary"`

	// ConsensusBackend is the consensus backend for all the nodes.
	ConsensusBackend string `json:"consensus_backend"`

	// ConsensusTimeoutCommit is the consensus commit timeout.
	ConsensusTimeoutCommit time.Duration `json:"consensus_timeout_commit"`

	// HaltEpoch is the halt epoch height flag.
	HaltEpoch uint64 `json:"halt_epoch"`

	// EpochtimeMock is the mock epochtime flag.
	EpochtimeMock bool `json:"epochtime_mock"`

	// EpochtimeTendermintInterval is the tendermint epochtime block interval.
	EpochtimeTendermintInterval int64 `json:"epochtime_tendermint_interval"`

	// DeterministicIdentities is the deterministic identities flag.
	DeterministicIdentities bool `json:"deterministic_identities"`

	// IASUseRegistry specifies whether the IAS proxy should use the registry instead of the
	// genesis document for authenticating runtime IDs.
	IASUseRegistry bool `json:"ias_use_registry,omitempty"`

	// StakingGenesis is the name of a file with a staking genesis document to use if GenesisFile isn't set.
	StakingGenesis string `json:"staking_genesis"`

	// A set of log watcher handler factories used by default on all nodes
	// created in this test network.
	DefaultLogWatcherHandlerFactories []log.WatcherHandlerFactory `json:"-"`
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

// Keymanager returns the keymanagers associated with the network.
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

// CloseLogWatchers closes all log watchers and checks if any errors were reported
// while the log watchers were running.
func (net *Network) CheckLogWatchers() (err error) {
	for _, w := range net.logWatchers {
		w.Cleanup()
		if logErr := <-w.Errors(); logErr != nil {
			net.logger.Error("log watcher reported error",
				"name", w.Name(),
				"err", logErr,
			)
			err = errors.Wrapf(logErr, "log watcher %s", w.Name())
		}
	}
	return
}

// Start starts the network.
func (net *Network) Start() error {
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
		if err := net.makeGenesis(); err != nil {
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

	net.logger.Debug("provisioning seed node")
	if _, err = net.newSeedNode(); err != nil {
		net.logger.Error("failed to provision seed node",
			"err", err,
		)
		return err
	}

	net.logger.Debug("starting IAS proxy node")
	if net.iasProxy != nil {
		if err = net.iasProxy.startNode(); err != nil {
			net.logger.Error("failed to start IAS proxy node",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting seed node")
	if err = net.seedNode.startNode(); err != nil {
		net.logger.Error("failed to start seed node",
			"err", err,
		)
		return err
	}

	net.logger.Debug("starting validator node(s)")
	for _, v := range net.validators {
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
		// port), and you launch all the validators near simultaniously, there
		// is a high chance that at least one of the validators will get upset
		// and start refusing connections.
		time.Sleep(validatorStartDelay)
	}

	for _, km := range net.keymanagers {
		net.logger.Debug("starting keymanager")
		if err = km.startNode(); err != nil {
			net.logger.Error("failed to start keymanager node",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting storage node(s)")
	for _, v := range net.storageWorkers {
		if err = v.startNode(); err != nil {
			net.logger.Error("failed to start storage worker",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting compute node(s)")
	for _, v := range net.computeWorkers {
		if err = v.startNode(); err != nil {
			net.logger.Error("failed to start compute worker",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting sentry node(s)")
	for _, v := range net.sentries {
		if err = v.startNode(); err != nil {
			net.logger.Error("failed to start sentry node",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting client node(s)")
	for _, v := range net.clients {
		if err = v.startNode(); err != nil {
			net.logger.Error("failed to start client node",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting byzantine node(s)")
	for _, v := range net.byzantine {
		if err = v.startNode(); err != nil {
			net.logger.Error("failed to start byzantine node",
				"err", err,
			)
			return err
		}
	}

	// Use the first validator as a controller.
	if len(net.validators) >= 1 {
		if net.controller, err = NewController(net.validators[0].SocketPath()); err != nil {
			net.logger.Error("failed to create controller",
				"err", err,
			)
			return errors.Wrap(err, "oasis: failed to create controller")
		}
	}
	// Create a client controller for the first client node.
	if len(net.clients) >= 1 {
		if net.clientController, err = NewController(net.clients[0].SocketPath()); err != nil {
			net.logger.Error("failed to create client controller",
				"err", err,
			)
			return errors.Wrap(err, "oasis: failed to create client controller")
		}
	}

	net.logger.Info("network started")

	return nil
}

// Stop stops the network.
func (net *Network) Stop() {
	net.env.Cleanup()
}

func (net *Network) runNodeBinary(consoleWriter io.Writer, args ...string) error {
	nodeBinary := net.cfg.NodeBinary
	cmd := exec.Command(nodeBinary, args...)
	cmd.SysProcAttr = CmdAttrs
	if consoleWriter != nil {
		cmd.Stdout = consoleWriter
		cmd.Stderr = consoleWriter
	}

	net.logger.Info("launching node",
		"args", strings.Join(args, " "),
	)

	return cmd.Run()
}

func (net *Network) generateDeterministicNodeIdentity(dir *env.Dir, rawSeed string) error {
	h := crypto.SHA512.New()
	_, _ = h.Write([]byte(rawSeed))
	seed := h.Sum(nil)

	rng, err := drbg.New(crypto.SHA512, seed, nil, []byte("deterministic node identities test"))
	if err != nil {
		return err
	}

	factory := fileSigner.NewFactory(dir.String(), signature.SignerNode)
	if _, err = factory.Generate(signature.SignerNode, rng); err != nil {
		return err
	}
	return nil
}

func (net *Network) startOasisNode(
	dir *env.Dir,
	subCmd []string,
	extraArgs *argBuilder,
	descr string,
	termEarlyOk bool,
	restartable bool,
) (*exec.Cmd, chan error, error) {
	baseArgs := []string{
		"--" + common.CfgDataDir, dir.String(),
		"--log.level", "debug",
		"--log.format", "json",
		"--log.file", nodeLogPath(dir),
		"--genesis.file", net.GenesisPath(),
	}
	if len(subCmd) == 0 {
		extraArgs = extraArgs.
			appendIASProxy(net.iasProxy).
			tendermintDebugAddrBookLenient().
			tendermintDebugAllowDuplicateIP()
	}
	args := append([]string{}, subCmd...)
	args = append(args, baseArgs...)
	args = append(args, extraArgs.vec...)

	w, err := dir.NewLogWriter(logConsoleFile)
	if err != nil {
		return nil, nil, err
	}
	net.env.AddOnCleanup(func() {
		_ = w.Close()
	})

	oasisBinary := net.cfg.NodeBinary
	cmd := exec.Command(oasisBinary, args...)
	cmd.SysProcAttr = CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	net.logger.Info("launching Oasis node",
		"args", strings.Join(args, " "),
	)

	if err = cmd.Start(); err != nil {
		return nil, nil, errors.Wrap(err, "oasis: failed to start node")
	}

	doneCh := net.env.AddTermOnCleanup(cmd)
	exitCh := make(chan error, 1)
	go func() {
		cmdErr := <-doneCh
		net.logger.Debug("node terminated",
			"err", cmdErr,
		)

		if cmdErr != nil {
			exitCh <- cmdErr
		}
		close(exitCh)

		if cmdErr != nil && !restartable && (cmdErr != env.ErrEarlyTerm || !termEarlyOk) {
			net.errCh <- errors.Wrapf(cmdErr, "oasis: %s node terminated", descr)
		}
	}()

	return cmd, exitCh, nil
}

func (net *Network) makeGenesis() error {
	args := []string{
		"genesis", "init",
		"--genesis.file", net.GenesisPath(),
		"--chain.id", genesisTestHelpers.TestChainID,
		"--halt.epoch", strconv.FormatUint(net.cfg.HaltEpoch, 10),
		"--consensus.backend", net.cfg.ConsensusBackend,
		"--epochtime.tendermint.interval", strconv.FormatInt(net.cfg.EpochtimeTendermintInterval, 10),
		"--consensus.tendermint.timeout_commit", net.cfg.ConsensusTimeoutCommit.String(),
		"--registry.debug.allow_unroutable_addresses", "true",
		"--" + genesis.CfgRegistryDebugAllowTestRuntimes, "true",
		"--scheduler.max_validators_per_entity", strconv.Itoa(len(net.Validators())),
	}
	if net.cfg.EpochtimeMock {
		args = append(args, "--epochtime.debug.mock_backend")
	}
	if net.cfg.DeterministicIdentities {
		args = append(args, "--beacon.debug.deterministic")
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
	for _, v := range net.keymanagers {
		if err := v.provisionGenesis(); err != nil {
			return err
		}
		args = append(args, v.toGenesisArgs()...)
	}
	if net.cfg.StakingGenesis != "" {
		args = append(args, "--staking", net.cfg.StakingGenesis)
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
		return errors.Wrap(err, "oasis: failed to create genesis file")
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

func (net *Network) provisionNodeIdentity(dataDir *env.Dir, seed string) (signature.PublicKey, error) {
	if net.cfg.DeterministicIdentities {
		if err := net.generateDeterministicNodeIdentity(dataDir, seed); err != nil {
			return signature.PublicKey{}, errors.Wrap(err, "oasis: failed to generate deterministic identity")
		}
	}

	signerFactory := fileSigner.NewFactory(dataDir.String(), signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	nodeIdentity, err := identity.LoadOrGenerate(dataDir.String(), signerFactory)
	if err != nil {
		return signature.PublicKey{}, errors.Wrap(err, "oasis: failed to provision node identity")
	}
	return nodeIdentity.NodeSigner.Public(), nil
}

// New creates a new test Oasis network.
func New(env *env.Env, cfg *NetworkCfg) (*Network, error) {
	baseDir, err := env.NewSubDir("network")
	if err != nil {
		return nil, errors.Wrap(err, "oasis: failed to create network sub-directory")
	}

	// Copy the config and apply some sane defaults.
	cfgCopy := *cfg
	if cfgCopy.ConsensusBackend == "" {
		cfgCopy.ConsensusBackend = defaultConsensusBackend
	}
	if cfgCopy.ConsensusTimeoutCommit == 0 {
		cfgCopy.ConsensusTimeoutCommit = defaultConsensusTimeoutCommit
	}
	if cfgCopy.EpochtimeTendermintInterval == 0 {
		cfgCopy.EpochtimeTendermintInterval = defaultEpochtimeTendermintInterval
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
	return filepath.Join(dir.String(), internalSocketFile)
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
