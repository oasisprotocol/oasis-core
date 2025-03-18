package node

import (
	"errors"
	"fmt"
	"os"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/background"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/pprof"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
)

// initCommon initializes the common environment across all commands.
func initCommon() error {
	if err := cmdCommon.Init(); err != nil {
		// Common stuff like logger not correctly initialized.
		_, _ = fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}

// verifyElevatedPrivileges checks if the user has elevated privileges or not.
func verifyElevatedPrivileges(logger *logging.Logger) error {
	canRun, isRoot := cmdCommon.IsNotRootOrAllowed()
	if !canRun {
		err := errors.New("running with elevated privileges not allowed")
		logger.Error(err.Error())
		return err
	}
	if isRoot {
		// The flags for allowing running as root must be set, warn.
		// If something bad happens, Don't Blame Oasis.
		logger.Warn("running with elevated privileges is NOT RECOMMENDED")
	}

	return nil
}

// configureDataDir configures data directory.
func configureDataDir(logger *logging.Logger) (string, error) {
	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		err := errors.New("data directory not configured")
		logger.Error(err.Error())
		return "", err
	}
	return dataDir, nil
}

// loadOrGenerateIdentity generates or loads the node identity.
func loadOrGenerateIdentity(dataDir string, logger *logging.Logger) (*identity.Identity, error) {
	signerFactory, err := cmdSigner.NewFactory(cmdSigner.Backend(), dataDir, identity.RequiredSignerRoles...)
	if err != nil {
		logger.Error("failed to initialize signer backend",
			"err", err,
		)
		return nil, err
	}
	identity, err := identity.LoadOrGenerate(dataDir, signerFactory)
	if err != nil {
		logger.Error("failed to load/generate identity",
			"err", err,
		)
		return nil, err
	}

	logger.Info("loaded/generated node identity",
		"node_pk", identity.NodeSigner.Public(),
		"p2p_pk", identity.P2PSigner.Public(),
		"consensus_pk", identity.ConsensusSigner.Public(),
		"tls_pk", identity.TLSSigner.Public(),
	)

	return identity, nil
}

// startMetricServer initializes and starts the metrics reporting server.
func startMetricServer(svcMgr *background.ServiceManager, logger *logging.Logger) (service.BackgroundService, error) {
	// Initialize the metrics server.
	metrics, err := metrics.New(svcMgr.Ctx)
	if err != nil {
		logger.Error("failed to initialize metrics server",
			"err", err,
		)
		return nil, err
	}
	svcMgr.Register(metrics)

	// Start the metrics reporting server.
	if err = metrics.Start(); err != nil {
		logger.Error("failed to start metrics reporting server",
			"err", err,
		)
		return nil, err
	}

	return metrics, nil
}

// startProfilingServer initializes and starts the profiling server.
func startProfilingServer(svcMgr *background.ServiceManager, logger *logging.Logger) (service.BackgroundService, error) {
	// Initialize the profiling server.
	profiling, err := pprof.New()
	if err != nil {
		logger.Error("failed to initialize pprof server",
			"err", err,
		)
		return nil, err
	}
	svcMgr.Register(profiling)

	// Start the profiling server.
	if err = profiling.Start(); err != nil {
		logger.Error("failed to start pprof server",
			"err", err,
		)
		return nil, err
	}

	return profiling, nil
}
