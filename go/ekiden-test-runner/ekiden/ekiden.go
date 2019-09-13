// Package ekiden provides the ekiden network/node/client related test helpers.
package ekiden

import (
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
)

const (
	baseNodePort = 20000

	validatorStartDelay = 3 * time.Second

	defaultConsensusBackend            = "tendermint"
	defaultConsensusTimeoutCommit      = 250 * time.Millisecond
	defaultEpochtimeBackend            = "tendermint"
	defaultEpochtimeTendermintInterval = 30

	internalSocketFile = "internal.sock"

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

	seedNode *seedNode
	iasProxy *iasProxy

	cfg          *NetworkCfg
	nextNodePort uint16

	errCh chan error
}

// NetworkCfg is the ekiden test network configuration.
type NetworkCfg struct {
	// EkidenBinary is the path to the ekiden binary.
	EkidenBinary string

	// RuntimeLoaderBinary is the path to the ekiden runtime loader.
	RuntimeLoaderBinary string

	// ConsensusBackend is the consensus backend for all the nodes.
	ConsensusBackend string

	// ConsensusTimeoutCommit is the consensus commit timeout.
	ConsensusTimeoutCommit time.Duration

	// EpochtimeBackend is the epochtime backend.
	EpochtimeBackend string

	// EpochtimeTendermintInterval is the tendermint epochtime block interval.
	EpochtimeTendermintInterval uint

	// XXX: Config for IAS proxy
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

// Errors returns the channel by which node failres will be conveyed.
func (net *Network) Errors() <-chan error {
	return net.errCh
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

	net.logger.Debug("provisioning genesis doc")
	if err := net.makeGenesis(); err != nil {
		net.logger.Error("failed to create genesis document",
			"err", err,
		)
		return err
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

	net.logger.Info("network started")

	return nil
}

func (net *Network) runEkidenBinary(consoleWriter io.Writer, args ...string) error {
	cmd := exec.Command(net.cfg.EkidenBinary, args...)
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

func (net *Network) startEkidenNode(dir *env.Dir, subCmd []string, extraArgs *argBuilder, descr string) error {
	baseArgs := []string{
		"--datadir", dir.String(),
		"--log.level", "debug",
		"--log.file", nodeLogPath(dir),
		"--metrics.mode", "none",
		"--genesis.file", net.genesisPath(),
	}
	if len(subCmd) == 0 {
		baseArgs = append(baseArgs, "--tendermint.debug.addr_book_lenient")
		extraArgs = extraArgs.appendIASProxy(net.iasProxy)
	}
	args := append([]string{}, subCmd...)
	args = append(args, baseArgs...)
	args = append(args, extraArgs.vec...)

	w, err := dir.NewLogWriter("console.log")
	if err != nil {
		return err
	}
	net.env.AddOnCleanup(func() {
		_ = w.Close()
	})

	cmd := exec.Command(net.cfg.EkidenBinary, args...)
	cmd.SysProcAttr = CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	net.logger.Info("launching ekiden node",
		"args", strings.Join(args, " "),
	)

	if err = cmd.Start(); err != nil {
		return errors.Wrap(err, "ekiden: failed to start node")
	}

	doneCh := net.env.AddTermOnCleanup(cmd)
	go func() {
		cmdErr := <-doneCh
		if cmdErr != nil {
			net.errCh <- errors.Wrapf(cmdErr, "ekiden: %s node terminated", descr)
		}
	}()

	return nil
}

func (net *Network) makeGenesis() error {
	args := []string{
		"genesis", "init",
		"--genesis.file", net.genesisPath(),
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
		args = append(args, net.keymanager.toGenesisArgs()...)
	}
	// ${roothash_genesis_blocks:+--roothash ${roothash_genesis_blocks}}

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
	return filepath.Join(net.baseDir.String(), "genesis.json")
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
	return filepath.Join(dir.String(), "node.log")
}
