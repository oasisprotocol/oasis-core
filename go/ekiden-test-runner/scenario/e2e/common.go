// Package e2e implements the ekiden e2e test scenarios.
package e2e

import (
	"fmt"
	"os/exec"

	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/sgx"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/ekiden"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
)

const (
	cfgEkidenBinary     = "e2e.ekiden.binary"
	cfgClientBinary     = "e2e.client.binary"
	cfgRuntimeBinary    = "e2e.runtime.binary"
	cfgRuntimeLoader    = "e2e.runtime.loader"
	cfgKeymanagerBinary = "e2e.keymanager.binary"
	cfgTEEHardware      = "e2e.tee_hardware"

	numValidators = 3
	numCompute    = 3
	numStorage    = 2
)

var (
	// Flags is the command line flags for the e2e tests.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)

	runtimeID    signature.PublicKey
	keymanagerID signature.PublicKey

	testMrsigner sgx.Mrsigner
)

func startClient(env *env.Env, net *ekiden.Network) (*exec.Cmd, error) {
	clients := net.Clients()
	if len(clients) == 0 {
		return nil, fmt.Errorf("scenario/e2e: network has no client nodes")
	}

	d, err := env.NewSubDir("client")
	if err != nil {
		return nil, err
	}

	w, err := d.NewLogWriter("client.log")
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(
		viper.GetString(cfgClientBinary),
		"--node-address", "unix:"+clients[0].SocketPath(),
		"--runtime-id", runtimeID.String(),
	)
	cmd.SysProcAttr = ekiden.CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	// XXX: log the args...

	if err = cmd.Start(); err != nil {
		return nil, errors.Wrap(err, "scenario/e2e: failed to start client")
	}

	return cmd, nil
}

func init() {
	Flags.String(cfgEkidenBinary, "ekiden", "path to the ekiden binary")
	Flags.String(cfgClientBinary, "simple-keyvalue-client", "path to the client binary")
	Flags.String(cfgRuntimeBinary, "simple-keyvalue", "path to the runtime binary")
	Flags.String(cfgRuntimeLoader, "ekiden-runtime-loader", "path to the runtime loader")
	Flags.String(cfgKeymanagerBinary, "ekiden-keymanager-runtime", "path to the keymanager runtime")
	Flags.String(cfgTEEHardware, "", "TEE hardware to use")
	_ = viper.BindPFlags(Flags)

	_ = runtimeID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")
	_ = keymanagerID.UnmarshalHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	_ = testMrsigner.UnmarshalHex("9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a")
}
