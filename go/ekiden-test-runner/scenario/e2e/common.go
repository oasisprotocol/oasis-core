// Package e2e implements the ekiden e2e test scenarios.
package e2e

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/ekiden"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
)

const (
	cfgEkidenBinary     = "e2e.ekiden.binary"
	cfgClientBinaryDir  = "e2e.client.binary_dir"
	cfgRuntimeBinary    = "e2e.runtime.binary"
	cfgRuntimeLoader    = "e2e.runtime.loader"
	cfgKeymanagerBinary = "e2e.keymanager.binary"
	cfgTEEHardware      = "e2e.tee_hardware"
)

var (
	// Flags is the command line flags for the e2e tests.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)

	runtimeID    signature.PublicKey
	keymanagerID signature.PublicKey

	logger = logging.GetLogger("e2e/common")
)

func startClient(env *env.Env, net *ekiden.Network, clientBinary string, clientArgs []string) (*exec.Cmd, error) {
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

	binary := filepath.Join(viper.GetString(cfgClientBinaryDir), clientBinary)
	args := []string{
		"--node-address", "unix:" + clients[0].SocketPath(),
		"--runtime-id", runtimeID.String(),
	}
	args = append(args, clientArgs...)

	cmd := exec.Command(binary, args...)
	cmd.SysProcAttr = ekiden.CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	logger.Info("launching client",
		"binary", binary,
		"args", strings.Join(args, " "),
	)

	if err = cmd.Start(); err != nil {
		return nil, errors.Wrap(err, "scenario/e2e: failed to start client")
	}

	return cmd, nil
}

func startSubCommand(env *env.Env, name, binary string, args []string) (*exec.Cmd, error) {
	d, err := env.NewSubDir(name)
	if err != nil {
		return nil, err
	}

	w, err := d.NewLogWriter("command.log")
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(binary, args...)
	cmd.SysProcAttr = ekiden.CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	logger.Info("launching subcommand",
		"binary", binary,
		"args", strings.Join(args, " "),
	)

	if err = cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func runSubCommand(env *env.Env, name, binary string, args []string) error {
	cmd, err := startSubCommand(env, name, binary, args)
	if err != nil {
		return err
	}
	if err = cmd.Wait(); err != nil {
		return err
	}
	return nil
}

func init() {
	Flags.String(cfgEkidenBinary, "ekiden", "path to the ekiden binary")
	Flags.String(cfgClientBinaryDir, "", "path to the client binaries directory")
	Flags.String(cfgRuntimeBinary, "simple-keyvalue", "path to the runtime binary")
	Flags.String(cfgRuntimeLoader, "ekiden-runtime-loader", "path to the runtime loader")
	Flags.String(cfgKeymanagerBinary, "ekiden-keymanager-runtime", "path to the keymanager runtime")
	Flags.String(cfgTEEHardware, "", "TEE hardware to use")
	_ = viper.BindPFlags(Flags)

	_ = runtimeID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")
	_ = keymanagerID.UnmarshalHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
}
