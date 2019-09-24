// Package ekiden provides the ekiden network/node/client related test helpers.
package ekiden

import (
	"crypto"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/drbg"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/log"
)

const (
	baseNodePort = 20000

	validatorStartDelay = 3 * time.Second

	defaultConsensusBackend            = "tendermint"
	defaultConsensusTimeoutCommit      = 250 * time.Millisecond
	defaultEpochtimeBackend            = "tendermint"
	defaultEpochtimeTendermintInterval = 30

	internalSocketFile = "internal.sock"

	logNodeFile    = "node.log"
	logConsoleFile = "console.log"

	maxNodes = 32 // Arbitrary
)

// CmdAttrs is the SysProcAttr that will ensure graceful cleanup.
var CmdAttrs = &syscall.SysProcAttr{
	Pdeathsig: syscall.SIGKILL,
}

// Network is a test ekiden network.
type Network struct {
	logger *logging.Logger

	env     *env.Env
	baseDir *env.Dir

	entities       []*Entity
	validators     []*Validator
	runtimes       []*Runtime
	keymanager     *Keymanager
	storageWorkers []*Storage
	computeWorkers []*Compute
	clients        []*Client
	byzantine      []*Byzantine

	seedNode *seedNode
	iasProxy *iasProxy

	cfg          *NetworkCfg
	nextNodePort uint16

	logWatchers []*log.Watcher

	controller *Controller

	errCh chan error
}

// NetworkCfg is the ekiden test network configuration.
type NetworkCfg struct {
	// GenesisFile is an optional genesis file to use.
	GenesisFile string `json:"genesis_file,omitempty"`

	// EkidenBinary is the path to the ekiden binary.
	EkidenBinary string `json:"ekiden_binary"`

	// RuntimeLoaderBinary is the path to the ekiden runtime loader.
	RuntimeLoaderBinary string `json:"runtime_loader_binary"`

	// ConsensusBackend is the consensus backend for all the nodes.
	ConsensusBackend string `json:"consensus_backend"`

	// ConsensusTimeoutCommit is the consensus commit timeout.
	ConsensusTimeoutCommit time.Duration `json:"consensus_timeout_commit"`

	// EpochtimeBackend is the epochtime backend.
	EpochtimeBackend string `json:"epochtime_backend"`

	// EpochtimeTendermintInterval is the tendermint epochtime block interval.
	EpochtimeTendermintInterval uint `json:"epochtime_tendermint_interval"`

	// DeterministicIdentities is the deterministic identities flag.
	DeterministicIdentities bool `json:"deterministic_identities"`

	// XXX: Config for IAS proxy

	// A set of log watcher handlers used by default on all nodes created in
	// this test network.
	LogWatcherHandlers []log.WatcherHandler `json:"-"`
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

// Keymanager returns the keymanager associated with the network.
func (net *Network) Keymanager() *Keymanager {
	return net.keymanager
}

// StorageWorkers returns the storage worker nodes associated with the network.
func (net *Network) StorageWorkers() []*Storage {
	return net.storageWorkers
}

// ComputeWorkers returns the compute worker nodes associated with the network.
func (net *Network) ComputeWorkers() []*Compute {
	return net.computeWorkers
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

// NumRegisterNodes returns the number of all nodes that need to register.
func (net *Network) NumRegisterNodes() int {
	return len(net.validators) +
		1 + // Key manager.
		len(net.storageWorkers) +
		len(net.computeWorkers) +
		len(net.byzantine)
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

	net.logger.Debug("provisioning seed node")
	if _, err := net.newSeedNode(); err != nil {
		net.logger.Error("failed to provision seed node",
			"err", err,
		)
		return err
	}

	net.logger.Debug("starting IAS proxy node")
	if net.iasProxy != nil {
		if err := net.iasProxy.startNode(); err != nil {
			net.logger.Error("failed to start IAS proxy node",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting seed node")
	if err := net.seedNode.startNode(); err != nil {
		net.logger.Error("failed to start seed node",
			"err", err,
		)
		return err
	}

	net.logger.Debug("starting validator node(s)")
	for _, v := range net.validators {
		if err := v.startNode(); err != nil {
			net.logger.Error("failed to start validator",
				"err", err,
			)
			return err
		}

		// HACK HACK HACK HACK HACK
		//
		// If you don't attempt to start the Tendermint Prometheus HTTP server
		// (even if it is doomed to fail due to ekiden already listening on the
		// port), and you launch all the validators near simultaniously, there
		// is a high chance that at least one of the validators will get upset
		// and start refusing connections.
		time.Sleep(validatorStartDelay)
	}

	if net.keymanager != nil {
		net.logger.Debug("starting keymanager")
		if err := net.keymanager.startNode(); err != nil {
			net.logger.Error("failed to start keymanager node",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting storage node(s)")
	for _, v := range net.storageWorkers {
		if err := v.startNode(); err != nil {
			net.logger.Error("failed to start storage worker",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting compute node(s)")
	for _, v := range net.computeWorkers {
		if err := v.startNode(); err != nil {
			net.logger.Error("failed to start compute worker",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting client node(s)")
	for _, v := range net.clients {
		if err := v.startNode(); err != nil {
			net.logger.Error("failed to start client worker",
				"err", err,
			)
			return err
		}
	}

	net.logger.Debug("starting byzantine node(s)")
	for _, v := range net.byzantine {
		if err := v.startNode(); err != nil {
			net.logger.Error("failed to start byzantine node",
				"err", err,
			)
			return err
		}
	}

	net.logger.Info("network started")

	return nil
}

// Stop stops the network.
func (net *Network) Stop() {
	net.env.Cleanup()
}

func (net *Network) runEkidenBinary(consoleWriter io.Writer, args ...string) error {
	ekidenBinary := net.cfg.EkidenBinary
	cmd := exec.Command(ekidenBinary, args...)
	cmd.SysProcAttr = CmdAttrs
	if consoleWriter != nil {
		cmd.Stdout = consoleWriter
		cmd.Stderr = consoleWriter
	}

	net.logger.Info("launching ekiden",
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

func (net *Network) startEkidenNode(
	dir *env.Dir,
	subCmd []string,
	extraArgs *argBuilder,
	descr string,
	termEarlyOk bool,
	restartable bool,
) (*exec.Cmd, error) {
	baseArgs := []string{
		"--datadir", dir.String(),
		"--log.level", "debug",
		"--log.format", "json",
		"--log.file", nodeLogPath(dir),
		"--genesis.file", net.genesisPath(),
	}
	if len(subCmd) == 0 {
		extraArgs = extraArgs.
			appendIASProxy(net.iasProxy).
			tendermintDebugAddrBookLenient()
	}
	args := append([]string{}, subCmd...)
	args = append(args, baseArgs...)
	args = append(args, extraArgs.vec...)

	w, err := dir.NewLogWriter(logConsoleFile)
	if err != nil {
		return nil, err
	}
	net.env.AddOnCleanup(func() {
		_ = w.Close()
	})

	ekidenBinary := net.cfg.EkidenBinary
	cmd := exec.Command(ekidenBinary, args...)
	cmd.SysProcAttr = CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	net.logger.Info("launching ekiden node",
		"args", strings.Join(args, " "),
	)

	if err = cmd.Start(); err != nil {
		return nil, errors.Wrap(err, "ekiden: failed to start node")
	}

	if len(net.cfg.LogWatcherHandlers) > 0 {
		logFileWatcher, err := log.NewWatcher(&log.WatcherConfig{
			Name:     fmt.Sprintf("%s/log", descr),
			File:     nodeLogPath(dir),
			Handlers: net.cfg.LogWatcherHandlers,
		})
		if err != nil {
			return nil, err
		}
		net.env.AddOnCleanup(logFileWatcher.Cleanup)
		net.logWatchers = append(net.logWatchers, logFileWatcher)
	}

	doneCh := net.env.AddTermOnCleanup(cmd)
	go func() {
		cmdErr := <-doneCh
		net.logger.Debug("node terminated",
			"err", cmdErr,
		)

		if cmdErr != nil && !restartable && (cmdErr != env.ErrEarlyTerm || !termEarlyOk) {
			net.errCh <- errors.Wrapf(cmdErr, "ekiden: %s node terminated", descr)
		}
	}()

	return cmd, nil
}

func (net *Network) makeGenesis() error {
	args := []string{
		"genesis", "init",
		"--genesis.file", net.genesisPath(),
		"--chain.id", "ekiden-test-runner",
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
	if net.keymanager != nil {
		if err := net.keymanager.provisionGenesis(); err != nil {
			return err
		}
		args = append(args, net.keymanager.toGenesisArgs()...)
	}

	w, err := net.baseDir.NewLogWriter("genesis_provision.log")
	if err != nil {
		return err
	}
	defer w.Close()

	if err := net.runEkidenBinary(w, args...); err != nil {
		net.logger.Error("failed to create genesis file",
			"err", err,
		)
		return errors.Wrap(err, "ekiden: failed to create genesis file")
	}

	return nil
}

func (net *Network) genesisPath() string {
	if net.cfg.GenesisFile != "" {
		return net.cfg.GenesisFile
	}
	return filepath.Join(net.baseDir.String(), "genesis.json")
}

// BasePath returns the path to the network base directory.
func (net *Network) BasePath() string {
	return net.baseDir.String()
}

// New creates a new test ekiden network.
func New(env *env.Env, cfg *NetworkCfg) (*Network, error) {
	baseDir, err := env.NewSubDir("network")
	if err != nil {
		return nil, errors.Wrap(err, "ekiden: failed to create network sub-directory")
	}

	// Copy the config and apply some sane defaults.
	cfgCopy := *cfg
	if cfgCopy.ConsensusBackend == "" {
		cfgCopy.ConsensusBackend = defaultConsensusBackend
	}
	if cfgCopy.ConsensusTimeoutCommit == 0 {
		cfgCopy.ConsensusTimeoutCommit = defaultConsensusTimeoutCommit
	}
	if cfgCopy.EpochtimeBackend == "" {
		cfgCopy.EpochtimeBackend = defaultEpochtimeBackend
	}
	if cfgCopy.EpochtimeTendermintInterval == 0 {
		cfgCopy.EpochtimeTendermintInterval = defaultEpochtimeTendermintInterval
	}

	return &Network{
		logger:       logging.GetLogger("ekiden/" + env.Name()),
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

func nodeTLSKeyPath(dir *env.Dir) string {
	path, _ := identity.TLSCertPaths(dir.String())
	return path
}

func nodeTLSCertPath(dir *env.Dir) string {
	_, path := identity.TLSCertPaths(dir.String())
	return path
}
