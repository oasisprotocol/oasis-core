// Package cli contains helpers for various oasis-node subcommands.
package cli

import (
	"bytes"
	"io"
	"os/exec"
	"strings"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
)

type helpersBase struct {
	env *env.Env
	net *oasis.Network

	logger *logging.Logger
}

func (b *helpersBase) runSubCommand(name string, args []string) error {
	return RunSubCommand(b.env, b.logger, name, b.net.Config().NodeBinary, args)
}

func (b *helpersBase) runSubCommandWithOutput(name string, args []string) (bytes.Buffer, error) {
	return RunSubCommandWithOutput(b.env, b.logger, name, b.net.Config().NodeBinary, args)
}

// Helpers are the oasis-node cli helpers.
type Helpers struct {
	Consensus *ConsensusHelpers
	Registry  *RegistryHelpers
}

// New creates new oasis-node cli helpers.
func New(env *env.Env, net *oasis.Network, logger *logging.Logger) *Helpers {
	base := &helpersBase{
		env:    env,
		net:    net,
		logger: logger,
	}

	return &Helpers{
		Consensus: &ConsensusHelpers{base},
		Registry:  &RegistryHelpers{base},
	}
}

// StartSubCommand launches an oasis-node subcommand.
//
// It does not wait for the subcommand to complete.
func StartSubCommand(env *env.Env, logger *logging.Logger, name, binary string, args []string, stdout io.Writer, stderr io.Writer) (*exec.Cmd, error) {
	cmd := exec.Command(binary, args...)
	cmd.SysProcAttr = oasis.CmdAttrs
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	logger.Info("launching subcommand",
		"binary", binary,
		"args", strings.Join(args, " "),
	)

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// RunSubCommand launches an oasis-node subcommand and waits for it to complete.
//
// Stdout and stderr are redirected into a command-specific file.
func RunSubCommand(env *env.Env, logger *logging.Logger, name, binary string, args []string) error {
	d, err := env.NewSubDir(name)
	if err != nil {
		return err
	}

	w, err := d.NewLogWriter("command.log")
	if err != nil {
		return err
	}

	cmd, err := StartSubCommand(env, logger, name, binary, args, w, w)
	if err != nil {
		return err
	}
	if err = cmd.Wait(); err != nil {
		return err
	}
	return nil
}

// RunSubCommandWithOutput launches an oasis-node subcommand and waits for it to complete.
//
// Stdout and stderr are redirected into a buffer.
func RunSubCommandWithOutput(env *env.Env, logger *logging.Logger, name, binary string, args []string) (bytes.Buffer, error) {
	var b bytes.Buffer
	cmd, err := StartSubCommand(env, logger, name, binary, args, &b, &b)
	if err != nil {
		return b, err
	}
	if err = cmd.Wait(); err != nil {
		return b, err
	}
	return b, nil
}
