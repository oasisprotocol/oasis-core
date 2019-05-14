// Package keymanager implements the key manager worker.
package keymanager

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/ias"
	"github.com/oasislabs/ekiden/go/worker/common/host"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

const (
	cfgEnabled = "keymanager.enabled"

	cfgTEEHardware   = "keymanager.tee_hardware"
	cfgRuntimeLoader = "keymanager.loader"
	cfgRuntimeBinary = "keymanager.runtime"
	cfgPort          = "keymanager.port"
	// XXX: RuntimeID

	rpcCallTimeout = 5 * time.Second
)

var (
	_ service.BackgroundService = (*worker)(nil)

	emptyRoot hash.Hash
)

type worker struct {
	enabled bool

	stopCh chan struct{}
	quitCh chan struct{}

	runtimeID    signature.PublicKey
	workerHost   host.Host
	localStorage *host.LocalStorage
	grpc         *grpc.Server

	logger *logging.Logger
}

func (w *worker) Name() string {
	return "key manager worker"
}

func (w *worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting key manager as it is disabled")
		return nil
	}

	w.logger.Info("starting key manager service")

	if err := w.workerHost.Start(); err != nil {
		return err
	}

	if err := w.grpc.Start(); err != nil {
		return err
	}

	return nil
}

func (w *worker) Stop() {
	defer close(w.quitCh)

	w.logger.Info("stopping key manager service")

	if !w.enabled {
		return
	}

	// Stop the sub-components.
	close(w.stopCh)

	w.grpc.Stop()
	w.workerHost.Stop()

	w.localStorage.Stop()
}

func (w *worker) Quit() <-chan struct{} {
	return w.quitCh
}

func (w *worker) Cleanup() {
}

func (w *worker) callLocal(ctx context.Context, data []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancel()

	req := &protocol.Body{
		WorkerRPCCallRequest: &protocol.WorkerRPCCallRequest{
			Request:   data,
			StateRoot: emptyRoot,
		},
	}

	ch, err := w.workerHost.MakeRequest(ctx, req)
	if err != nil {
		w.logger.Error("failed to dispatch RPC call to worker host",
			"err", err,
		)
		return nil, err
	}

	select {
	case response := <-ch:
		if response == nil {
			w.logger.Error("channel closed durring RPC call",
				"err", io.EOF,
			)
			return nil, errors.Wrap(io.EOF, "worker/keymanager: channel closed during RPC call")
		}

		if response.Error != nil {
			w.logger.Error("error from runtime",
				"err", response.Error.Message,
			)
			return nil, fmt.Errorf("worker/keymanager: error from runtime: %s", response.Error.Message)
		}

		resp := response.WorkerRPCCallResponse
		if resp == nil {
			w.logger.Error("malformed response from worker",
				"response", response,
			)
			return nil, fmt.Errorf("worker/keymanager: malformed response from worker")
		}

		return resp.Response, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-w.stopCh:
		return nil, fmt.Errorf("worker/keymanager: terminating")
	}
}

// New constructs a new key manager worker.
func New(dataDir string, ias *ias.IAS, identity *identity.Identity) (service.BackgroundService, error) {
	var teeHardware node.TEEHardware
	s := viper.GetString(cfgTEEHardware)
	switch strings.ToLower(s) {
	case "", "invalid":
	case "intel-sgx":
		teeHardware = node.TEEHardwareIntelSGX
	default:
		return nil, fmt.Errorf("invalid TEE hardware: %s", s)
	}

	workerRuntimeLoaderBinary := viper.GetString(cfgRuntimeLoader)
	runtimeBinary := viper.GetString(cfgRuntimeBinary)
	port := uint16(viper.GetInt(cfgPort))
	// XXX: RuntimeID

	w := &worker{
		enabled: viper.GetBool(cfgEnabled),
		stopCh:  make(chan struct{}),
		quitCh:  make(chan struct{}),
		logger:  logging.GetLogger("worker/keymanager"),
	}
	_ = w.runtimeID.UnmarshalHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

	if w.enabled {
		if workerRuntimeLoaderBinary == "" {
			return nil, fmt.Errorf("worker/keymanager: worker runtime loader binary not configured")
		}
		if runtimeBinary == "" {
			return nil, fmt.Errorf("worker/keymanager: runtime binary not configured")
		}

		var err error
		if w.localStorage, err = host.NewLocalStorage(dataDir, "km-local-storage.bolt.db"); err != nil {
			return nil, errors.Wrap(err, "worker/keymanager: failed to open local storage")
		}

		if w.workerHost, err = host.NewSandboxedHost(
			"keymanager",
			workerRuntimeLoaderBinary,
			runtimeBinary,
			make(map[string]host.ProxySpecification),
			teeHardware,
			ias,
			newHostHandler(w),
			false,
		); err != nil {
			return nil, errors.Wrap(err, "worker/keymanager: failed to create worker host")
		}
		// XXX: Register the on-(re)start hook.

		if w.grpc, err = grpc.NewServerTCP("keymanager", port, identity.TLSCertificate); err != nil {
			return nil, errors.Wrap(err, "worker/keymanager: failed to create gRPC server")
		}
		newEnclaveRPCGRPCServer(w)
	}

	return w, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgEnabled, false, "Enable key manager process")

		cmd.Flags().String(cfgTEEHardware, "", "TEE hardware to use for the key manager")
		cmd.Flags().String(cfgRuntimeLoader, "", "Path to key manager worker process binary")
		cmd.Flags().String(cfgRuntimeBinary, "", "Path to key manager runtime binary")
		cmd.Flags().Uint16(cfgPort, 9003, "Port to use for incoming key manager gRPC connections")
		// XXX: RuntimeID
	}

	for _, v := range []string{
		cfgEnabled,

		cfgTEEHardware,
		cfgRuntimeLoader,
		cfgRuntimeBinary,
		cfgPort,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}

func init() {
	emptyRoot.Empty()
}
