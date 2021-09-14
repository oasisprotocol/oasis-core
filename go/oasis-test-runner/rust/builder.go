// Package rust contains a Go interface to the Rust build system.
//
// This is needed as certain E2E tests require things to be rebuilt during tests.
package rust

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
)

const (
	builderSubDir         = "cargo-builder"
	builderLogConsoleFile = "console.log"
)

// Builder provides an interface for building Rust runtimes by invoking `cargo`.
type Builder struct {
	env *env.Env

	teeHardware node.TEEHardware
	pkg         string

	buildDir  string
	targetDir string

	envVars map[string]string
}

// SetEnv sets a build-time environment variable.
func (b *Builder) SetEnv(key, value string) {
	b.envVars[key] = value
}

// ResetEnv resets the build-time environment variables.
func (b *Builder) ResetEnv() {
	b.envVars = make(map[string]string)
}

func (b *Builder) cargoCommand(subCommand string) (*exec.Cmd, error) {
	dir, err := b.env.NewSubDir(builderSubDir)
	if err != nil {
		return nil, err
	}
	w, err := dir.NewLogWriter(builderLogConsoleFile)
	if err != nil {
		return nil, err
	}
	b.env.AddOnCleanup(func() {
		_ = w.Close()
	})

	cmd := exec.Command("cargo", subCommand)
	cmd.Dir = b.buildDir
	cmd.SysProcAttr = env.CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	targetDir := b.targetDir
	if b.teeHardware == node.TEEHardwareIntelSGX {
		targetDir = filepath.Join(targetDir, "sgx")
	} else {
		targetDir = filepath.Join(targetDir, "default")
	}

	cmd.Env = append(os.Environ(),
		fmt.Sprintf("CARGO_TARGET_DIR=%s", targetDir),
	)

	return cmd, nil
}

// Build starts the build process.
func (b *Builder) Build() error {
	cmd, err := b.cargoCommand("build")
	if err != nil {
		return err
	}
	cmd.Args = append(cmd.Args, "--package", b.pkg)

	if b.teeHardware == node.TEEHardwareIntelSGX {
		cmd.Args = append(cmd.Args, "--target", "x86_64-fortanix-unknown-sgx")
	}

	for k, v := range b.envVars {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	if err = cmd.Run(); err != nil {
		return fmt.Errorf("failed to build runtime with trust root: %w", err)
	}

	// When building for SGX, also convert the ELF binary to SGXS format.
	if b.teeHardware == node.TEEHardwareIntelSGX {
		if cmd, err = b.cargoCommand("elf2sgxs"); err != nil {
			return fmt.Errorf("failed to elf2sgxs runtime: %w", err)
		}
		if err = cmd.Run(); err != nil {
			return fmt.Errorf("failed to elf2sgxs runtime: %w", err)
		}
	}
	return nil
}

// NewBuilder creates a new builder for Rust runtimes.
func NewBuilder(
	env *env.Env,
	teeHardware node.TEEHardware,
	pkg string,
	buildDir string,
	targetDir string,
) *Builder {
	return &Builder{
		env:         env,
		teeHardware: teeHardware,
		pkg:         pkg,
		buildDir:    buildDir,
		targetDir:   targetDir,
		envVars:     make(map[string]string),
	}
}
