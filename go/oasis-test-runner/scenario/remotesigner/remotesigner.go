// Package remotesigner implements the Oasis remote-signer test scenarios.
package remotesigner

import (
	flag "github.com/spf13/pflag"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/cmd"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

const (
	// cfgServerBinary is path to remote-signer server executable.
	cfgServerBinary = "binary"
)

// RemoteSignerParamsDummy is a dummy instance of remoteSignerImpl used to register global
// remote-signer flags.
var RemoteSignerParamsDummy = newRemoteSignerImpl("")

type remoteSignerImpl struct {
	name   string
	logger *logging.Logger
	flags  *env.ParameterFlagSet
}

func newRemoteSignerImpl(name string) *remoteSignerImpl {
	// Empty scenario name is used for registering global parameters only.
	fullName := "remote-signer"
	if name != "" {
		fullName += "/" + name
	}

	sc := &remoteSignerImpl{
		name:   fullName,
		logger: logging.GetLogger("scenario/" + fullName),
		flags:  env.NewParameterFlagSet(fullName, flag.ContinueOnError),
	}
	sc.flags.String(cfgServerBinary, "oasis-remote-signer", "remote signer binary")

	return sc
}

func (sc *remoteSignerImpl) Clone() remoteSignerImpl {
	return remoteSignerImpl{
		name:   sc.name,
		logger: sc.logger,
		flags:  sc.flags.Clone(),
	}
}

func (sc *remoteSignerImpl) Name() string {
	return sc.name
}

func (sc *remoteSignerImpl) Parameters() *env.ParameterFlagSet {
	return sc.flags
}

func (sc *remoteSignerImpl) PreInit(childEnv *env.Env) error {
	return nil
}

func (sc *remoteSignerImpl) Fixture() (*oasis.NetworkFixture, error) {
	return nil, nil
}

func (sc *remoteSignerImpl) Init(childEnv *env.Env, net *oasis.Network) error {
	return nil
}

// RegisterScenarios registers all scenarios for remote-signer.
func RegisterScenarios() error {
	// Register non-scenario-specific parameters.
	cmd.RegisterScenarioParams(RemoteSignerParamsDummy.Name(), RemoteSignerParamsDummy.Parameters())

	// Register default scenarios which are executed, if no test names provided.
	for _, s := range []scenario.Scenario{
		// Basic remote signer test case.
		Basic,
	} {
		if err := cmd.Register(s); err != nil {
			return err
		}
	}

	return nil
}
