// Package oasis provides the Oasis network/node/client related test helpers.
package oasis

import (
	"context"
	"crypto/x509"
	"fmt"
	"math"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	commonNode "github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
)

const (
	baseNodePort = 20000

	validatorStartDelay = 3 * time.Second

	defaultConsensusBackend            = "tendermint"
	defaultEpochtimeTendermintInterval = 30
	defaultInitialHeight               = 1
	defaultHaltEpoch                   = math.MaxUint64

	defaultConsensusTimeoutCommit = 1 * time.Second

	defaultVRFAlphaThreshold  = 3
	defaultVRFInterval        = 20
	defaultVRFSubmissionDelay = 5

	logNodeFile        = "node.log"
	logConsoleFile     = "console.log"
	exportsDir         = "exports"
	stakingGenesisFile = "staking_genesis.json"

	maxNodes = 32 // Arbitrary

	nodePortConsensus = "consensus"
	nodePortClient    = "client"
	nodePortP2P       = "p2p"
	nodePortPprof     = "pprof"
)

// ConsensusStateSyncCfg is a node's consensus state sync configuration.
type ConsensusStateSyncCfg struct {
	ConsensusNodes []string
	TrustHeight    uint64
	TrustHash      string
}

// Feature is a feature or worker hosted by a concrete oasis-node process.
type Feature interface {
	AddArgs(args *argBuilder) error
}

// CustomStartFeature is a feature with a customized start method.
type CustomStartFeature interface {
	CustomStart(args *argBuilder) error
}

type hostedRuntime struct {
	runtime     *Runtime
	tee         commonNode.TEEHardware
	binaryIdx   int
	localConfig map[string]interface{}
}

// Node defines the common fields for all node types.
type Node struct { // nolint: maligned
	sync.Mutex

	Name   string
	NodeID signature.PublicKey

	net *Network
	dir *env.Dir
	cmd *exec.Cmd

	extraArgs      []Argument
	features       []Feature
	hasValidators  bool
	assignedPorts  map[string]uint16
	hostedRuntimes map[common.Namespace]*hostedRuntime

	exitCh chan error

	termEarlyOk bool
	termErrorOk bool
	isStopping  bool
	noAutoStart bool

	crashPointsProbability      float64
	supplementarySanityInterval uint64

	disableDefaultLogWatcherHandlerFactories bool
	logWatcherHandlerFactories               []log.WatcherHandlerFactory

	consensus            ConsensusFixture
	consensusStateSync   *ConsensusStateSyncCfg
	customGrpcSocketPath string

	pprofPort uint16

	nodeSigner signature.PublicKey
	p2pSigner  signature.PublicKey
	sentryCert *x509.Certificate

	entity *Entity
}

func (n *Node) getProvisionedPort(portName string) uint16 {
	port, ok := n.assignedPorts[portName]
	if !ok {
		port = n.net.nextNodePort
		n.net.nextNodePort++
		n.assignedPorts[portName] = port
	}
	return port
}

func (n *Node) addHostedRuntime(rt *Runtime, tee commonNode.TEEHardware, binaryIdx int, localConfig map[string]interface{}) {
	hosted, ok := n.hostedRuntimes[rt.id]
	if !ok {
		n.hostedRuntimes[rt.id] = &hostedRuntime{
			runtime:     rt,
			tee:         tee,
			binaryIdx:   binaryIdx,
			localConfig: localConfig,
		}
		return
	}

	if tee > hosted.tee {
		hosted.tee = tee
	}
	if binaryIdx != hosted.binaryIdx {
		panic(fmt.Sprintf("oasis/node: conflicting runtime binary index (%d vs. %d)", binaryIdx, hosted.binaryIdx))
	}
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
	factory, err := fileSigner.NewFactory(n.dir.String(), identity.RequiredSignerRoles...)
	if err != nil {
		return nil, err
	}
	return identity.Load(n.dir.String(), factory)
}

// Start starts the node.
func (n *Node) Start() error {
	args := newArgBuilder()
	var customStart CustomStartFeature

	// Reset hosted runtimes as various AddArgs will be populating them.
	n.hostedRuntimes = make(map[common.Namespace]*hostedRuntime)

	for _, f := range n.features {
		if err := f.AddArgs(args); err != nil {
			return fmt.Errorf("oasis/node: failed to add arguments for feature on node %s: %w", n.Name, err)
		}
		if cf, ok := f.(CustomStartFeature); ok {
			if customStart != nil {
				return fmt.Errorf("oasis/node: multiple features with customized startup on node %s", n.Name)
			}
			customStart = cf
		}
	}
	for _, hosted := range n.hostedRuntimes {
		args.appendHostedRuntime(hosted.runtime, hosted.tee, hosted.binaryIdx, hosted.localConfig)
	}

	args.extraArgs(n.extraArgs)

	if customStart != nil {
		return customStart.CustomStart(args)
	}

	if err := n.net.startOasisNode(n, nil, args); err != nil {
		return fmt.Errorf("oasis/node: failed to launch node %s: %w", n.Name, err)
	}

	return nil
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
	return n.Start()
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

func (n *Node) setProvisionedIdentity(persistTLS bool, seed string) error {
	if len(seed) < 1 {
		seed = n.Name
	}
	if n.sentryCert != nil {
		return nil
	}

	nodeSigner, p2pSigner, sentryCert, err := n.net.provisionNodeIdentity(n.dir, seed, persistTLS)
	if err != nil {
		return err
	}

	if err := n.entity.addNode(nodeSigner); err != nil {
		return err
	}

	n.nodeSigner = nodeSigner
	n.p2pSigner = p2pSigner
	n.sentryCert = sentryCert
	copy(n.NodeID[:], nodeSigner[:])

	return nil
}

// NodeCfg defines the common node configuration options.
type NodeCfg struct { // nolint: maligned
	Name string

	AllowEarlyTermination       bool
	AllowErrorTermination       bool
	CrashPointsProbability      float64
	SupplementarySanityInterval uint64
	EnableProfiling             bool

	NoAutoStart bool

	DisableDefaultLogWatcherHandlerFactories bool
	LogWatcherHandlerFactories               []log.WatcherHandlerFactory

	// Consensus contains configuration for the consensus backend.
	Consensus ConsensusFixture

	Entity *Entity

	ExtraArgs []Argument
}

// Into sets node parameters of an existing node object from the configuration.
func (cfg *NodeCfg) Into(node *Node) {
	node.noAutoStart = cfg.NoAutoStart
	node.termEarlyOk = cfg.AllowEarlyTermination
	node.termErrorOk = cfg.AllowErrorTermination
	node.crashPointsProbability = cfg.CrashPointsProbability
	node.supplementarySanityInterval = cfg.SupplementarySanityInterval
	node.disableDefaultLogWatcherHandlerFactories = cfg.DisableDefaultLogWatcherHandlerFactories
	node.logWatcherHandlerFactories = cfg.LogWatcherHandlerFactories
	node.consensus = cfg.Consensus
	if node.entity != nil && cfg.Entity != nil && node.entity != cfg.Entity {
		panic(fmt.Sprintf("oasis: entity mismatch for node %s", node.Name))
	}
	if cfg.Entity != nil {
		node.entity = cfg.Entity
	}

	if node.pprofPort == 0 && cfg.EnableProfiling {
		node.pprofPort = node.getProvisionedPort(nodePortPprof)
	}
	node.extraArgs = cfg.ExtraArgs
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
