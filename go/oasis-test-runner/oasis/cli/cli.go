// Package cli contains helpers for various oasis-node subcommands.
package cli

import (
	"bytes"
	"io"
	"os/exec"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdNode "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/node"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
)

// Factory is an interface that can be used to construct CLI helpers.
type Factory interface {
	// GetCLIConfig returns the configuration required for constructing a CLI helper.
	GetCLIConfig() Config
}

// Config is the CLI helper configuration.
type Config struct {
	// NodeBinary is the path to the oasis-node binary file.
	NodeBinary string

	// GenesisFile is the path to the genesis document.
	GenesisFile string

	// NodeSocketPath is the path to the internal UNIX socket of a node that should be used for any
	// commands which require talking to a working oasis-node.
	NodeSocketPath string
}

type helpersBase struct {
	env *env.Env
	cfg Config

	logger *logging.Logger
}

func (b *helpersBase) runSubCommand(name string, args []string) error {
	return RunSubCommand(b.env, b.logger, name, b.cfg.NodeBinary, args)
}

func (b *helpersBase) runSubCommandWithOutput(name string, args []string) (bytes.Buffer, error) {
	return RunSubCommandWithOutput(b.env, b.logger, name, b.cfg.NodeBinary, args)
}

// Helpers are the oasis-node cli helpers.
type Helpers struct {
	*helpersBase

	Consensus  *ConsensusHelpers
	Registry   *RegistryHelpers
	Keymanager *KeymanagerHelpers
}

// New creates new oasis-node cli helpers.
func New(env *env.Env, factory Factory, logger *logging.Logger) *Helpers {
	base := &helpersBase{
		env:    env,
		cfg:    factory.GetCLIConfig(),
		logger: logger,
	}

	return &Helpers{
		helpersBase: base,
		Consensus:   &ConsensusHelpers{base},
		Registry:    &RegistryHelpers{base},
		Keymanager:  &KeymanagerHelpers{base},
	}
}

// UnsafeReset launches the unsafe-reset subcommand, clearing all consensus and (optionally)
// runtime state.
func (h *Helpers) UnsafeReset(dataDir string, preserveRuntimeStorage, preserveLocalStorage, force bool) error {
	args := []string{"unsafe-reset", "--" + cmdCommon.CfgDataDir, dataDir}
	if !preserveRuntimeStorage {
		args = append(args, "--"+cmdNode.CfgPreserveMKVSDatabase+"=false")
	}
	if !preserveLocalStorage {
		args = append(args, "--"+cmdNode.CfgPreserveLocalStorage+"=false")
	}
	if force {
		args = append(args, "--force")
	}
	return h.runSubCommand("unsafe-reset", args)
}

// StartSubCommand launches an oasis-node subcommand.
//
// It does not wait for the subcommand to complete.
func StartSubCommand(childEnv *env.Env, logger *logging.Logger, name, binary string, args []string, stdout, stderr io.Writer) (*exec.Cmd, error) {
	cmd := exec.Command(binary, args...)
	cmd.SysProcAttr = env.CmdAttrs
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
