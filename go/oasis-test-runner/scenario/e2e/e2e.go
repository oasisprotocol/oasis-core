// Package e2e implements the Oasis e2e test scenarios.
package e2e

import (
	flag "github.com/spf13/pflag"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/cmd"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

const (
	cfgNodeBinary = "node.binary"
)

var (
	// E2eParamsDummy is a dummy instance of e2eImpl used to register e2e-wise parameters.
	E2eParamsDummy *e2eImpl = &e2eImpl{name: "e2e"}

	logger = logging.GetLogger("e2e/common")
)

// e2eImpl is a base class for tests involving oasis-node.
type e2eImpl struct {
	net    *oasis.Network
	name   string
	logger *logging.Logger

	// nodeBinary is the path to oasis-node executable.
	nodeBinary string
}

func newE2eImpl(name string) *e2eImpl {
	return &e2eImpl{
		name:       "e2e/" + name,
		logger:     logging.GetLogger("scenario/e2e/" + name),
		nodeBinary: "oasis-node",
	}
}

func (sc *e2eImpl) Clone() e2eImpl {
	return e2eImpl{
		net:        sc.net,
		name:       sc.name,
		logger:     sc.logger,
		nodeBinary: sc.nodeBinary,
	}
}

func (sc *e2eImpl) Name() string {
	return sc.name
}

func (sc *e2eImpl) Parameters() *flag.FlagSet {
	fs := flag.NewFlagSet(sc.name, flag.ContinueOnError)
	fs.StringVar(&sc.nodeBinary, cfgNodeBinary, sc.nodeBinary, "path to the node binary")

	return fs
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
