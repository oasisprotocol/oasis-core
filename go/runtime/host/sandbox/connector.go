package sandbox

import (
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox/process"
)

// ConnectorFactoryFunc is the runtime connector factory function.
type ConnectorFactoryFunc func(logger *logging.Logger, runtimeDir string, sandboxed bool) (Connector, error)

// Connector is the runtime connection establishment interface.
type Connector interface {
	// ConfigureSandbox configures the process sandbox if needed.
	ConfigureSandbox(cfg *process.Config) error

	// Connect establishes a connection to the runtime.
	Connect(p process.Process) (net.Conn, error)

	// Close releases any resources associated with the connector.
	Close()
}

// UnixSocketConnector is a runtime connector that uses a UNIX socket to communicate with the
// runtime.
type UnixSocketConnector struct {
	socketPath string
	sandboxed  bool
	listener   *net.UnixListener
	logger     *logging.Logger
}

// NewUnixSocketConnector returns a new UNIX socket connector.
func NewUnixSocketConnector(logger *logging.Logger, runtimeDir string, sandboxed bool) (Connector, error) {
	hostSocket := filepath.Join(runtimeDir, "host.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: hostSocket})
	if err != nil {
		return nil, fmt.Errorf("failed to create host socket: %w", err)
	}

	return &UnixSocketConnector{
		listener:   listener,
		socketPath: hostSocket,
		sandboxed:  sandboxed,
		logger:     logger,
	}, nil
}

// GetHostSocketPath returns the UNIX socket path on the host.
func (us *UnixSocketConnector) GetHostSocketPath() string {
	return us.socketPath
}

// GetGuestSocketPath returns the UNIX socket path on the guest.
func (us *UnixSocketConnector) GetGuestSocketPath() string {
	if !us.sandboxed {
		return us.socketPath
	}
	return "/host.sock"
}

// ConfigureSandbox configures the process sandbox if needed.
func (us *UnixSocketConnector) ConfigureSandbox(cfg *process.Config) error {
	if !us.sandboxed {
		return nil
	}
	cfg.BindRW[us.GetHostSocketPath()] = us.GetGuestSocketPath()
	return nil
}

// Connect establishes a connection to the runtime.
func (us *UnixSocketConnector) Connect(p process.Process) (net.Conn, error) {
	if us.listener == nil {
		return nil, fmt.Errorf("not initialized")
	}

	// Spawn goroutine that waits for a connection to be established.
	connCh := make(chan interface{})
	go func() {
		lerr := us.listener.SetDeadline(time.Now().Add(runtimeConnectTimeout))
		if lerr != nil {
			connCh <- lerr
			return
		}
		conn, lerr := us.listener.Accept()
		if lerr != nil {
			connCh <- lerr
			return
		}

		connCh <- conn
		close(connCh)
	}()

	var conn net.Conn
	select {
	case res := <-connCh:
		// Got a connection or timed out while accepting a connection.
		switch r := res.(type) {
		case error:
			return nil, fmt.Errorf("error while accepting runtime connection: %w", r)
		case net.Conn:
			conn = r
		default:
			panic("invalid type")
		}
	case <-p.Wait():
		// Runtime has terminated before a connection was accepted.
		us.logger.Debug("runtime process exited unexpectedly",
			"pid", p.GetPID(),
			"err", p.Error(),
		)

		return nil, fmt.Errorf("terminated while waiting for runtime to connect")
	}
	return conn, nil
}

// Close releases any resources associated with the connector.
func (us *UnixSocketConnector) Close() {
	if us.listener != nil {
		us.listener.Close()
		us.listener = nil
	}
	us.socketPath = ""
}
