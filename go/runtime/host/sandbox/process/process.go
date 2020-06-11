// Package process implements a process sandboxing mechanism.
package process

import (
	"io"
	"os"
)

// Config contains the sandbox configuration.
//
// This is similar to the os/exec.Cmd structure.
type Config struct {
	// Path is the path to the binary that should be executed inside the sandbox.
	Path string

	// Args are the arguments passed to the executed binary.
	Args []string

	// Environment variables passed to the executed binary.
	Env map[string]string

	// BindRW is a set of read-write binds into the sandbox.
	BindRW map[string]string

	// BindRO is a set of read-only binds into the sandbox.
	BindRO map[string]string

	// BindDev is a set of device binds into the sandbox.
	BindDev map[string]string

	// BindData is a set of byte readers that should be bound into the sandbox.
	BindData map[string]io.Reader

	// Stdout is the writer that should be used for standard output. If not specified, the current
	// process' os.Stdout will be used.
	Stdout io.Writer

	// Stderr is the writer that should be used for standard error. If not specified, the current
	// process' os.Stderr will be used.
	Stderr io.Writer

	// SandboxBinaryPath is the path to the sandbox support binary.
	SandboxBinaryPath string

	extraFiles []*os.File
}

// Process is a sandboxed process.
type Process interface {
	// GetPID returns the process identifier of the sandbox running the given process.
	GetPID() int

	// Wait returns a channel that is closed when the process terminates. To retrieve the reason for
	// the process termination, see Error().
	Wait() <-chan struct{}

	// Error returns the termination error (if any) for the process. In case the process has not yet
	// terminated it will return nil.
	Error() error

	// Kill causes the sandboxed process to exit immediately.
	Kill()
}
