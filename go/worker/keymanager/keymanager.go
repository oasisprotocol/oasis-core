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

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/ias"
	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/common/host"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
	"github.com/oasislabs/ekiden/go/worker/registration"
)

const (
	cfgEnabled = "worker.keymanager.enabled"

	cfgTEEHardware   = "worker.keymanager.tee_hardware"
	cfgRuntimeLoader = "worker.keymanager.runtime.loader"
	cfgRuntimeBinary = "worker.keymanager.runtime.binary"
	cfgRuntimeID     = "worker.keymanager.runtime.id"

	rpcCallTimeout = 5 * time.Second
)

var (
	_ service.BackgroundService = (*worker)(nil)

	emptyRoot hash.Hash
)

type worker struct {
	enabled bool

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	quitCh    chan struct{}
	initCh    chan struct{}

	runtimeID    signature.PublicKey
	workerHost   host.Host
	localStorage *host.LocalStorage
	grpc         *grpc.Server

	registration *registration.Registration

	logger *logging.Logger
}

func (w *worker) Name() string {
	return "key manager worker"
}

func (w *worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting key manager worker as it is disabled")
		close(w.initCh)

		return nil
	}

	w.logger.Info("starting key manager worker")

	if err := w.workerHost.Start(); err != nil {
		return err
	}

	close(w.initCh)

	return nil
}

func (w *worker) Stop() {
	defer close(w.quitCh)

	w.logger.Info("stopping key manager service")

	if !w.enabled {
		return
	}

	// Stop the sub-components.
	w.cancelCtx()
	close(w.stopCh)

	w.workerHost.Stop()

	w.localStorage.Stop()
}

func (w *worker) Quit() <-chan struct{} {
	return w.quitCh
}

func (w *worker) Cleanup() {
	if !w.enabled {
		return
	}

	w.workerHost.Cleanup()
	w.grpc.Cleanup()
}

func (w *worker) callLocal(ctx context.Context, data []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancel()

	select {
	case <-w.initCh:
	case <-ctx.Done():
		return nil, context.Canceled
	}

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

func (w *worker) onProcessStart(proto *protocol.Protocol) error {
	// Initialize the key manager.
	type InitRequest struct {
		// TODO: At some point this needs the policy, checksum, peers, etc.
	}
	type InitCall struct { // nolint: maligned
		Method string      `codec:"method"`
		Args   InitRequest `codec:"args"`
	}

	call := InitCall{
		Method: "init",
		Args:   InitRequest{},
	}
	req := &protocol.Body{
		WorkerLocalRPCCallRequest: &protocol.WorkerLocalRPCCallRequest{
			Request:   cbor.Marshal(&call),
			StateRoot: emptyRoot,
		},
	}

	resp, err := proto.Call(w.ctx, req)
	if err != nil {
		w.logger.Error("failed to initialize key manager enclave",
			"err", err,
		)
		return err
	}

	// TODO: Do something clever with the response.
	/*
		type InitResponse struct {
			IsSecure bool   `codec:"is_secure"`
			Checksum []byte `codec:"checksum"`
		}
	*/
	_ = resp

	return nil
}

func (w *worker) onNodeRegistration(n *node.Node) error {
	tee, err := w.workerHost.WaitForCapabilityTEE(w.ctx)
	if err != nil {
		w.logger.Error("failed to obtain CapabilityTEE",
			"err", err,
		)
		return err
	}

	// Add the key manager runtime to the node descriptor.  Done here instead
	// of in the registration's generic handler since the registration handler
	// only knows about normal runtimes.
	rtDesc := &node.Runtime{
		ID: w.runtimeID,
	}
	rtDesc.Capabilities.TEE = tee
	n.Runtimes = append(n.Runtimes, rtDesc)

	n.AddRoles(node.RoleKeyManager)

	return nil
}

// New constructs a new key manager worker.
func New(dataDir string, ias *ias.IAS, grpc *grpc.Server, r *registration.Registration, workerCommonCfg *workerCommon.Config) (service.BackgroundService, bool, error) {
	var teeHardware node.TEEHardware
	s := viper.GetString(cfgTEEHardware)
	switch strings.ToLower(s) {
	case "", "invalid":
	case "intel-sgx":
		teeHardware = node.TEEHardwareIntelSGX
	default:
		return nil, false, fmt.Errorf("invalid TEE hardware: %s", s)
	}

	workerRuntimeLoaderBinary := viper.GetString(cfgRuntimeLoader)
	runtimeBinary := viper.GetString(cfgRuntimeBinary)

	ctx, cancelFn := context.WithCancel(context.Background())

	w := &worker{
		enabled:      viper.GetBool(cfgEnabled),
		ctx:          ctx,
		cancelCtx:    cancelFn,
		stopCh:       make(chan struct{}),
		quitCh:       make(chan struct{}),
		initCh:       make(chan struct{}),
		grpc:         grpc,
		registration: r,
		logger:       logging.GetLogger("worker/keymanager"),
	}

	if w.enabled {
		if err := w.runtimeID.UnmarshalHex(viper.GetString(cfgRuntimeID)); err != nil {
			return nil, false, errors.Wrap(err, "worker/keymanager: failed to parse runtime ID")
		}

		if workerRuntimeLoaderBinary == "" {
			return nil, false, fmt.Errorf("worker/keymanager: worker runtime loader binary not configured")
		}
		if runtimeBinary == "" {
			return nil, false, fmt.Errorf("worker/keymanager: runtime binary not configured")
		}

		var err error
		if w.localStorage, err = host.NewLocalStorage(dataDir, "km-local-storage.bolt.db"); err != nil {
			return nil, false, errors.Wrap(err, "worker/keymanager: failed to open local storage")
		}

		w.registration.RegisterRole(w.onNodeRegistration)

		if w.workerHost, err = host.NewSandboxedHost(
			"keymanager",
			workerRuntimeLoaderBinary,
			runtimeBinary,
			make(map[string]host.ProxySpecification),
			teeHardware,
			ias,
			newHostHandler(w),
			w.onProcessStart,
			false,
		); err != nil {
			return nil, false, errors.Wrap(err, "worker/keymanager: failed to create worker host")
		}

		newEnclaveRPCGRPCServer(w)
	}

	return w, w.enabled, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgEnabled, false, "Enable key manager worker")

		cmd.Flags().String(cfgTEEHardware, "", "TEE hardware to use for the key manager")
		cmd.Flags().String(cfgRuntimeLoader, "", "Path to key manager worker process binary")
		cmd.Flags().String(cfgRuntimeBinary, "", "Path to key manager runtime binary")
		cmd.Flags().String(cfgRuntimeID, "", "Key manager Runtime ID")
	}

	for _, v := range []string{
		cfgEnabled,

		cfgTEEHardware,
		cfgRuntimeLoader,
		cfgRuntimeBinary,
		cfgRuntimeID,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}

func init() {
	emptyRoot.Empty()
}
