// Package e2e implements the Oasis e2e test scenarios.
package e2e

import (
	"context"

	flag "github.com/spf13/pflag"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/cmd"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

const (
	// cfgNodeBinary is the path to oasis-node executable.
	cfgNodeBinary = "node.binary"
)

// ParamsDummyScenario is a dummy instance of E2E scenario used to register global E2E flags.
var ParamsDummyScenario = NewScenario("")

// Scenario is a base scenario for oasis-node end-to-end tests.
type Scenario struct {
	Net    *oasis.Network
	Flags  *env.ParameterFlagSet
	Logger *logging.Logger

	name string
}

// NewScenario creates a new base scenario for oasis-node end-to-end tests.
func NewScenario(name string) *Scenario {
	// Empty scenario name is used for registering global parameters only.
	fullName := "e2e"
	if name != "" {
		fullName += "/" + name
	}

	sc := &Scenario{
		name:   fullName,
		Logger: logging.GetLogger("scenario/" + fullName),
		Flags:  env.NewParameterFlagSet(fullName, flag.ContinueOnError),
	}
	sc.Flags.String(cfgNodeBinary, "oasis-node", "path to the node binary")

	return sc
}

// Clone implements scenario.Scenario.
func (sc *Scenario) Clone() scenario.Scenario {
	return &Scenario{
		Net:    sc.Net,
		Flags:  sc.Flags.Clone(),
		Logger: sc.Logger,
		name:   sc.name,
	}
}

// Name implements scenario.Scenario.
func (sc *Scenario) Name() string {
	return sc.name
}

// Network implements scenario.Scenario.
func (sc *Scenario) Network() *oasis.Network {
	return sc.Net
}

// Parameters implements scenario.Scenario.
func (sc *Scenario) Parameters() *env.ParameterFlagSet {
	return sc.Flags
}

// PreInit implements scenario.Scenario.
func (sc *Scenario) PreInit() error {
	return nil
}

// Run implements scenario.Scenario.
func (sc *Scenario) Run(context.Context, *env.Env) error {
	return nil
}

// Fixture implements scenario.Scenario.
func (sc *Scenario) Fixture() (*oasis.NetworkFixture, error) {
	nodeBinary, _ := sc.Flags.GetString(cfgNodeBinary)

	return &oasis.NetworkFixture{
		Network: oasis.NetworkCfg{
			NodeBinary: nodeBinary,
			Consensus: consensusGenesis.Genesis{
				Parameters: consensusGenesis.Parameters{
					GasCosts: transaction.Costs{
						consensusGenesis.GasOpTxByte: 1,
					},
				},
			},
		},
		Entities: []oasis.EntityCfg{
			{IsDebugTestEntity: true},
			{},
		},
		Validators: []oasis.ValidatorFixture{
			{Entity: 1, Consensus: oasis.ConsensusFixture{SupplementarySanityInterval: 1}},
			{Entity: 1},
			{Entity: 1},
		},
		Seeds: []oasis.SeedFixture{{}},
	}, nil
}

// Init implements scenario.Scenario.
func (sc *Scenario) Init(_ *env.Env, net *oasis.Network) error {
	sc.Net = net
	return nil
}

// RegisterScenarios registers all end-to-end scenarios.
func RegisterScenarios() error {
	// Register non-scenario-specific parameters.
	cmd.RegisterScenarioParams(ParamsDummyScenario.Name(), ParamsDummyScenario.Parameters())

	// Register default scenarios which are executed, if no test names provided.
	for _, s := range []scenario.Scenario{
		// Gas fees tests.
		GasFeesStaking,
		GasFeesStakingDumpRestore,
		// Identity CLI test.
		IdentityCLI,
		// Genesis file test.
		GenesisFile,
		// Node upgrade tests.
		NodeUpgradeDummy,
		NodeUpgradeEmpty,
		NodeUpgradeCancel,
		// Debonding entries from genesis test.
		Debond,
		// Consensus state sync.
		ConsensusStateSync,
		// Multiple seeds test.
		MultipleSeeds,
		// Seed API test.
		SeedAPI,
		// ValidatorEquivocation test.
		ValidatorEquivocation,
		// Byzantine VRF beacon tests.
		ByzantineVRFBeaconHonest,
		ByzantineVRFBeaconEarly,
		ByzantineVRFBeaconMissing,
		// Minimum transact balance test.
		MinTransactBalance,
		// Consensus governance update parameters tests.
		ChangeParametersMinCommissionRate,
		// Consensus governance change reward schedule test.
		ChangeParametersRewardSchedule,
	} {
		if err := cmd.Register(s); err != nil {
			return err
		}
	}

	return nil
}
