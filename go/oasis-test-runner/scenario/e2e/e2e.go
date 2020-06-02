// Package e2e implements the Oasis e2e test scenarios.
package e2e

import (
	flag "github.com/spf13/pflag"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/cmd"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

const (
	// cfgNodeBinary is the path to oasis-node executable.
	cfgNodeBinary = "node.binary"
)

var (
	// E2eParamsDummy is a dummy instance of e2eImpl used to register global e2e flags.
	E2eParamsDummy *e2eImpl = newE2eImpl("")
)

// e2eImpl is a base class for tests involving oasis-node.
type e2eImpl struct {
	net    *oasis.Network
	name   string
	logger *logging.Logger
	flags  *env.ParameterFlagSet
}

func newE2eImpl(name string) *e2eImpl {
	// Empty scenario name is used for registering global parameters only.
	fullName := "e2e"
	if name != "" {
		fullName += "/" + name
	}

	sc := &e2eImpl{
		name:   fullName,
		logger: logging.GetLogger("scenario/" + fullName),
		flags:  env.NewParameterFlagSet(fullName, flag.ContinueOnError),
	}
	sc.flags.String(cfgNodeBinary, "oasis-node", "path to the node binary")

	return sc
}

func (sc *e2eImpl) Clone() e2eImpl {
	return e2eImpl{
		net:    sc.net,
		name:   sc.name,
		logger: sc.logger,
		flags:  sc.flags.Clone(),
	}
}

func (sc *e2eImpl) Name() string {
	return sc.name
}

func (sc *e2eImpl) Parameters() *env.ParameterFlagSet {
	return sc.flags
}

func (sc *e2eImpl) Init(childEnv *env.Env, net *oasis.Network) error {
	sc.net = net
	return nil
}

// RegisterScenarios registers all end-to-end scenarios.
func RegisterScenarios() error {
	// Register non-scenario-specific parameters.
	cmd.RegisterTestParams(E2eParamsDummy.Name(), E2eParamsDummy.Parameters())
	cmd.RegisterTestParams(RuntimeParamsDummy.Name(), RuntimeParamsDummy.Parameters())

	// Register default scenarios which are executed, if no test names provided.
	for _, s := range []scenario.Scenario{
		// Runtime test.
		Runtime,
		RuntimeEncryption,
		// Byzantine executor node.
		ByzantineExecutorHonest,
		ByzantineExecutorWrong,
		ByzantineExecutorStraggler,
		// Byzantine merge node.
		ByzantineMergeHonest,
		ByzantineMergeWrong,
		ByzantineMergeStraggler,
		// Storage sync test.
		StorageSync,
		// Sentry test.
		Sentry,
		SentryEncryption,
		// Keymanager restart test.
		KeymanagerRestart,
		// Keymanager replicate test.
		KeymanagerReplicate,
		// Dump/restore test.
		DumpRestore,
		// Halt test.
		HaltRestore,
		// Multiple runtimes test.
		MultipleRuntimes,
		// Registry CLI test.
		RegistryCLI,
		// Stake CLI test.
		StakeCLI,
		// Node shutdown test.
		NodeShutdown,
		// Gas fees tests.
		GasFeesStaking,
		GasFeesStakingDumpRestore,
		GasFeesRuntimes,
		// Identity CLI test.
		IdentityCLI,
		// Runtime prune test.
		RuntimePrune,
		// Runtime dynamic registration test.
		RuntimeDynamic,
		// Transaction source test.
		TxSourceMultiShort,
		// Node upgrade tests.
		NodeUpgrade,
		NodeUpgradeCancel,
		// Debonding entries from genesis test.
		Debond,
		// Late start test.
		LateStart,
		// Restore from v20.6 genesis file.
		RestoreV206,
		// KeymanagerUpgrade test.
		KeymanagerUpgrade,
	} {
		if err := cmd.Register(s); err != nil {
			return err
		}
	}

	// Register non-default scenarios which are executed on-demand only.
	for _, s := range []scenario.Scenario{
		// Transaction source test. Non-default, because it runs for ~6 hours.
		TxSourceMulti,
	} {
		if err := cmd.RegisterNondefault(s); err != nil {
			return err
		}
	}

	return nil
}
