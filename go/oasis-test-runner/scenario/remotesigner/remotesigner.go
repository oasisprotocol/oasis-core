// Package remotesigner implements the Oasis remote-signer test scenarios.
package remotesigner

import (
	flag "github.com/spf13/pflag"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/cmd"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

const (
	cfgServerBinary = "binary"
)

var (
	// RemoteSignerParamsDummy is a dummy instance of remoteSignerImpl used to register remote-signer-wise parameters.
	RemoteSignerParamsDummy *remoteSignerImpl = &remoteSignerImpl{name: "remote-signer"}
)

type remoteSignerImpl struct {
	name   string
	logger *logging.Logger

	// binary is the path to remote-signer server executable.
	serverBinary string
}

func newRemoteSignerImpl(name string) *remoteSignerImpl {
	return &remoteSignerImpl{
		name:         "remote-signer/" + name,
		logger:       logging.GetLogger("scenario/remote-signer/" + name),
		serverBinary: "oasis-remote-signer",
	}
}

func (sc *remoteSignerImpl) Clone() remoteSignerImpl {
	return remoteSignerImpl{
		name:         sc.name,
		logger:       sc.logger,
		serverBinary: sc.serverBinary,
	}
}

func (sc *remoteSignerImpl) Name() string {
	return sc.name
}

func (sc *remoteSignerImpl) Parameters() *flag.FlagSet {
	fs := flag.NewFlagSet(sc.Name(), flag.ContinueOnError)
	fs.StringVar(&sc.serverBinary, cfgServerBinary, sc.serverBinary, "runtime binary")

	return fs
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
	cmd.RegisterTestParams(RemoteSignerParamsDummy.Name(), RemoteSignerParamsDummy.Parameters())

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
