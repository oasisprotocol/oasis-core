package process

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/dynlib"
)

const (
	sandboxHostname = "oasis-core"

	sandboxMountBinary = "/entrypoint"
	sandboxMountLibDir = "/usr/lib"

	sandboxStartTimeout = 5 * time.Second
)

type bwrap struct {
	*naked
}

type fdPipeBuilder struct {
	pipes    []*os.File
	deadline time.Time
}

func (b *fdPipeBuilder) add() (*os.File, string, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, "", fmt.Errorf("failed to create pipe: %w", err)
	}

	if err = r.SetDeadline(b.deadline); err != nil {
		return nil, "", fmt.Errorf("failed to set deadline on read pipe: %w", err)
	}
	if err = w.SetDeadline(b.deadline); err != nil {
		return nil, "", fmt.Errorf("failed to set deadline on write pipe: %w", err)
	}

	// NOTE: Entry i becomes file descriptor 3+i.
	fdNum := 3 + len(b.pipes)
	b.pipes = append(b.pipes, r)

	return w, strconv.Itoa(fdNum), nil
}

func (b *fdPipeBuilder) close() {
	for _, p := range b.pipes {
		_ = p.Close()
	}
}

// NewBubbleWrap creates a Bubblewrap-based sandbox.
func NewBubbleWrap(cfg Config) (Process, error) {
	var fdPipes fdPipeBuilder
	// Make sure the sandbox starts in the given time.
	fdPipes.deadline = time.Now().Add(sandboxStartTimeout)
	defer fdPipes.close()

	// Prepare bwrap command-line arguments.
	fdArgsPipe, fdArgsNum, err := fdPipes.add()
	if err != nil {
		return nil, err
	}
	cliArgs := []string{
		// Pass all other arguments via a file descriptor.
		"--args", fdArgsNum,
		"--",
		sandboxMountBinary,
	}
	// Append entrypoint binary args.
	cliArgs = append(cliArgs, cfg.Args...)

	fdArgs := []string{
		// Unshare all possible namespaces.
		"--unshare-all",
		// Drop all capabilities.
		"--cap-drop", "ALL",
		// Ensure all workers have the same hostname.
		"--hostname", sandboxHostname,
		// Temporary directory.
		"--tmpfs", "/tmp",
		// A cut down /dev.
		"--dev", "/dev",
		// Kill worker when node exits.
		"--die-with-parent",
		// Start new terminal session.
		"--new-session",
		// Change working directory to /.
		"--chdir", "/",
		// Entrypoint binary.
		"--ro-bind", cfg.Path, sandboxMountBinary,
	}
	for key, value := range cfg.Env {
		fdArgs = append(fdArgs, "--setenv", key, value)
	}
	for path, mountPoint := range cfg.BindRW {
		fdArgs = append(fdArgs,
			"--dir", filepath.Dir(mountPoint),
			"--bind", path, mountPoint,
		)
	}
	for path, mountPoint := range cfg.BindRO {
		fdArgs = append(fdArgs,
			"--dir", filepath.Dir(mountPoint),
			"--ro-bind", path, mountPoint,
		)
	}
	for path, mountPoint := range cfg.BindDev {
		fdArgs = append(fdArgs, "--dev-bind", path, mountPoint)
	}

	// Resolve binary library dependencies so we can mount them in.
	cache, err := dynlib.LoadCache()
	if err != nil {
		return nil, fmt.Errorf("sandbox: failed to load dynamic library loader cache: %w", err)
	}
	libs, err := cache.ResolveLibraries(
		[]string{cfg.Path},
		[]string{},
		"",
		os.Getenv("LD_LIBRARY_PATH"),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("sandbox: failed to resolve worker binary libraries: %w", err)
	}

	// Bind all required libraries.
	for p, aliases := range libs {
		for _, alias := range aliases {
			mountDir := sandboxMountLibDir
			// The ld-linux-*.so library must be stored in /lib64 as otherwise the
			// binary will fail to start. All other libraries can be mounted to /usr/lib.
			if strings.HasPrefix(alias, "ld-linux") {
				mountDir = "/lib64"
			}

			fdArgs = append(fdArgs, "--ro-bind", p, filepath.Join(mountDir, alias))
		}
	}
	fdArgs = append(fdArgs, "--symlink", "/usr/lib", "/usr/lib64")

	// Create a pipe for passing the sandbox SECCOMP policy.
	seccompPipe, seccompNum, err := fdPipes.add()
	if err != nil {
		return nil, err
	}
	fdArgs = append(fdArgs, "--seccomp", seccompNum)

	// Create any pipes for passing data binds.
	type rwPipe struct {
		r io.Reader
		w io.WriteCloser
	}
	var dataPipes []rwPipe
	for path, reader := range cfg.BindData {
		pipe, fdNum, perr := fdPipes.add()
		if perr != nil {
			return nil, perr
		}

		fdArgs = append(fdArgs,
			"--dir", filepath.Dir(path),
			"--ro-bind-data", fdNum, path,
		)
		dataPipes = append(dataPipes, rwPipe{reader, pipe})
	}

	// Start our sandbox.
	n, err := NewNaked(Config{
		Path:   cfg.SandboxBinaryPath,
		Args:   cliArgs,
		Stdout: cfg.Stdout,
		Stderr: cfg.Stderr,
		// Pass all the pipe file descriptors.
		// NOTE: Entry i becomes file descriptor 3+i.
		extraFiles: fdPipes.pipes,
	})
	if err != nil {
		return nil, err
	}

	// Send configuration arguments.
	for _, arg := range fdArgs {
		if _, err = fdArgsPipe.Write([]byte(arg + "\x00")); err != nil {
			return nil, fmt.Errorf("sandbox: error while sending args to sandbox: %w", err)
		}
	}
	if err = fdArgsPipe.Close(); err != nil {
		return nil, fmt.Errorf("sandbox: error while sending args to sandbox: %w", err)
	}

	// Prepare and send SECCOMP policy.
	if err = generateSeccompPolicy(seccompPipe); err != nil {
		return nil, fmt.Errorf("sandbox: error while generating seccomp policy: %w", err)
	}
	if err = seccompPipe.Close(); err != nil {
		return nil, fmt.Errorf("sandbox: error while sending SECCOMP policy to sandbox: %w", err)
	}

	// Copy all the bound data.
	for _, p := range dataPipes {
		if _, err = io.Copy(p.w, p.r); err != nil {
			return nil, fmt.Errorf("sandbox: failed to copy bound data to sandbox: %w", err)
		}
		if err = p.w.Close(); err != nil {
			return nil, fmt.Errorf("sandbox: failed to copy bound data to sandbox: %w", err)
		}
	}

	return &bwrap{n.(*naked)}, nil
}
