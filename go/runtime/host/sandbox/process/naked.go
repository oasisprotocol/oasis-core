package process

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
)

type naked struct {
	sync.Mutex

	cmd *exec.Cmd

	err    error
	waitCh chan struct{}
}

// Implements Process.
func (n *naked) GetPID() int {
	return n.cmd.Process.Pid
}

// Implements Process.
func (n *naked) Wait() <-chan struct{} {
	return n.waitCh
}

// Implements Process.
func (n *naked) Error() (err error) {
	n.Lock()
	err = n.err
	n.Unlock()
	return
}

// Implements Process.
func (n *naked) Kill() {
	_ = n.cmd.Process.Kill()
	<-n.waitCh

	// Some environments (lolDocker) do not have something that
	// reaps zombie processes by default.  Kill the process group
	// as well.
	_ = syscall.Kill(-n.cmd.Process.Pid, syscall.SIGKILL)
}

func (n *naked) wait() error {
	err := n.cmd.Wait()
	if err != nil {
		// Error while waiting on process.
		return err
	} else if ps := n.cmd.ProcessState; !ps.Success() {
		// Processes dying due to a signal require special handling.
		if status, ok := ps.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				return fmt.Errorf("process died due to signal %s", status.Signal())
			}
		}

		// Process terminated with a non-zero exit code.
		return fmt.Errorf("process terminated with exit code %d", ps.Sys().(syscall.WaitStatus).ExitStatus())
	}

	return nil
}

// NewNaked creates a naked "sandbox" which performs no sandboxing and runs the given binary as a
// regular child process.
func NewNaked(cfg Config) (Process, error) {
	cmd := exec.Command(cfg.Path, cfg.Args...) // nolint: gosec
	// Setup environment variables.
	if cfg.Env != nil {
		for k, v := range cfg.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	// Forward stdout and stderr.
	if cfg.Stdout == nil {
		cfg.Stdout = os.Stdout
	}
	cmd.Stdout = cfg.Stdout
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}
	cmd.Stderr = cfg.Stderr
	cmd.ExtraFiles = cfg.extraFiles

	// Write any bound data to respective files.
	for path, reader := range cfg.BindData {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("failed to create directory for bound data: %w", err)
		}
		file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, fmt.Errorf("failed to write bound data: %w", err)
		}

		if _, err = io.Copy(file, reader); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("failed to copy bound data: %w", err)
		}
		if err = file.Close(); err != nil {
			return nil, fmt.Errorf("failed to copy bound data: %w", err)
		}
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	n := &naked{
		cmd:    cmd,
		waitCh: make(chan struct{}),
	}
	go func() {
		err := n.wait()

		n.Lock()
		n.err = err
		n.Unlock()

		close(n.waitCh)
	}()

	return n, nil
}
