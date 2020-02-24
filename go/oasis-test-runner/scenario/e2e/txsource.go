package e2e

import (
	"context"
	"crypto"
	"fmt"
	"math"
	"math/rand"
	"os/exec"
	"strings"
	"time"

	"github.com/oasislabs/oasis-core/go/common/crypto/drbg"
	"github.com/oasislabs/oasis-core/go/common/crypto/mathrand"
	"github.com/oasislabs/oasis-core/go/common/logging"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/txsource"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/txsource/workload"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

const (
	timeLimitShort = time.Minute
	timeLimitLong  = 43 * time.Minute

	nodeRestartIntervalLong = 2 * time.Minute
	livenessCheckInterval   = 1 * time.Minute
)

// TxSourceMultiShort uses multiple workloads for a short time.
var TxSourceMultiShort scenario.Scenario = &txSourceImpl{
	basicImpl: *newBasicImpl("txsource-multi-short", "", nil),
	workloads: []string{
		workload.NameTransfer,
		workload.NameOversized,
	},
	timeLimit:             timeLimitShort,
	livenessCheckInterval: livenessCheckInterval,
}

// TxSourceMulti uses multiple workloads.
var TxSourceMulti scenario.Scenario = &txSourceImpl{
	basicImpl: *newBasicImpl("txsource-multi", "", nil),
	workloads: []string{
		workload.NameTransfer,
		workload.NameOversized,
	},
	timeLimit:             timeLimitLong,
	nodeRestartInterval:   nodeRestartIntervalLong,
	livenessCheckInterval: livenessCheckInterval,
}

type txSourceImpl struct {
	basicImpl

	workloads             []string
	timeLimit             time.Duration
	nodeRestartInterval   time.Duration
	livenessCheckInterval time.Duration

	rng *rand.Rand
}

func (sc *txSourceImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}
	f.Network.StakingGenesis = "tests/fixture-data/txsource/staking-genesis.json"

	// Disable CheckTx on the client node so we can submit invalid transactions.
	f.Clients[0].ConsensusDisableCheckTx = true

	return f, nil
}

func (sc *txSourceImpl) Init(childEnv *env.Env, net *oasis.Network) error {
	sc.net = net

	// Set up the deterministic random source.
	hash := crypto.SHA512
	// TODO: Make the seed configurable.
	seed := []byte("seeeeeeeeeeeeeeeeeeeeeeeeeeeeeed")
	src, err := drbg.New(hash, seed, nil, []byte("txsource scenario"))
	if err != nil {
		return fmt.Errorf("failed to create random source: %w", err)
	}
	sc.rng = rand.New(mathrand.New(src))

	return nil
}

func (sc *txSourceImpl) manager(env *env.Env, errCh chan error) {
	// Make sure we exit when the environment gets torn down.
	stopCh := make(chan struct{})
	env.AddOnCleanup(func() { close(stopCh) })

	if sc.nodeRestartInterval > 0 {
		sc.logger.Info("random node restarts enabled",
			"restart_interval", sc.nodeRestartInterval,
		)
	} else {
		sc.nodeRestartInterval = math.MaxInt64
	}

	// Randomize node order.
	var nodes []*oasis.Node
	for _, v := range sc.net.Validators() {
		nodes = append(nodes, &v.Node)
	}
	// TODO: Consider including storage/compute workers.

	restartTicker := time.NewTicker(sc.nodeRestartInterval)
	defer restartTicker.Stop()

	livenessTicker := time.NewTicker(sc.livenessCheckInterval)
	defer livenessTicker.Stop()

	var nodeIndex int
	var lastHeight int64
	for {
		select {
		case <-stopCh:
			return
		case <-restartTicker.C:
			// Reshuffle nodes each time the counter wraps around.
			if nodeIndex == 0 {
				sc.rng.Shuffle(len(nodes), func(i, j int) {
					nodes[i], nodes[j] = nodes[j], nodes[i]
				})
			}

			// Choose a random node and restart it.
			node := nodes[nodeIndex]
			sc.logger.Info("restarting node",
				"node", node.Name,
			)

			if err := node.Restart(); err != nil {
				sc.logger.Error("failed to restart node",
					"node", node.Name,
					"err", err,
				)
				errCh <- err
				return
			}

			nodeIndex = (nodeIndex + 1) % len(nodes)
		case <-livenessTicker.C:
			// Check if consensus has made any progress.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			blk, err := sc.net.Controller().Consensus.GetBlock(ctx, consensus.HeightLatest)
			cancel()
			if err != nil {
				sc.logger.Warn("failed to query latest consensus block",
					"err", err,
				)
				continue
			}

			if blk.Height <= lastHeight {
				sc.logger.Error("consensus hasn't made any progress since last liveness check",
					"last_height", lastHeight,
					"height", blk.Height,
				)
				errCh <- fmt.Errorf("consensus is dead")
				return
			}

			sc.logger.Info("current consensus height",
				"height", blk.Height,
			)
			lastHeight = blk.Height
		}
	}
}

func (sc *txSourceImpl) startWorkload(childEnv *env.Env, errCh chan error, name string) error {
	sc.logger.Info("starting workload",
		"name", name,
	)

	d, err := childEnv.NewSubDir(fmt.Sprintf("workload-%s", name))
	if err != nil {
		return err
	}

	w, err := d.NewLogWriter(fmt.Sprintf("workload-%s.log", name))
	if err != nil {
		return err
	}

	logFmt := logging.FmtJSON
	logLevel := logging.LevelDebug

	args := []string{
		"debug", "txsource",
		"--address", "unix:" + sc.net.Clients()[0].SocketPath(),
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--log.format", logFmt.String(),
		"--log.level", logLevel.String(),
		"--" + flags.CfgGenesisFile, sc.net.GenesisPath(),
		"--" + txsource.CfgWorkload, name,
		"--" + txsource.CfgTimeLimit, sc.timeLimit.String(),
	}
	nodeBinary := sc.net.Config().NodeBinary

	cmd := exec.Command(nodeBinary, args...)
	cmd.SysProcAttr = oasis.CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	sc.logger.Info("launching workload binary",
		"args", strings.Join(args, " "),
	)

	if err = cmd.Start(); err != nil {
		return err
	}

	go func() {
		errCh <- cmd.Wait()

		sc.logger.Info("workload finished",
			"name", name,
		)
	}()

	return nil
}

func (sc *txSourceImpl) Run(childEnv *env.Env) error {
	if err := sc.net.Start(); err != nil {
		return fmt.Errorf("scenario net Start: %w", err)
	}

	// Wait for all nodes to be synced before we proceed.
	if err := sc.waitNodesSynced(); err != nil {
		return err
	}

	// Start all configured workloads.
	errCh := make(chan error, len(sc.workloads)+2)
	for _, name := range sc.workloads {
		if err := sc.startWorkload(childEnv, errCh, name); err != nil {
			return fmt.Errorf("failed to start workload %s: %w", name, err)
		}
	}
	// Start background scenario manager.
	go sc.manager(childEnv, errCh)

	// Wait for any workload to terminate.
	var err error
	select {
	case err = <-sc.net.Errors():
	case err = <-errCh:
	}
	if err != nil {
		return err
	}

	if err = sc.net.CheckLogWatchers(); err != nil {
		return err
	}

	return nil
}
