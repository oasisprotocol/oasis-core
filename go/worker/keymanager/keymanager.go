// Package keymanager implements the key manager worker.
package keymanager

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/ias"
	"github.com/oasislabs/ekiden/go/keymanager/api"
	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/common/host"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
	"github.com/oasislabs/ekiden/go/worker/registration"
)

const (
	// CfgEnabled enables the key manager worker.
	CfgEnabled = "worker.keymanager.enabled"

	// CfgTEEHardware configures the enclave TEE hardware.
	CfgTEEHardware = "worker.keymanager.tee_hardware"
	// CfgRuntimeLoader configures the runtime loader.
	CfgRuntimeLoader = "worker.keymanager.runtime.loader"
	// CfgRuntimeBinary configures the runtime binary.
	CfgRuntimeBinary = "worker.keymanager.runtime.binary"
	// CfgRuntimeID configures the runtime ID.
	CfgRuntimeID = "worker.keymanager.runtime.id"
	// CfgMayGenerate allows the enclave to generate a master secret.
	CfgMayGenerate = "worker.keymanager.may_generate"

	rpcCallTimeout = 5 * time.Second
)

var (
	_ service.BackgroundService = (*worker)(nil)

	errMalformedResponse = fmt.Errorf("worker/keymanager: malformed response from worker")

	emptyRoot hash.Hash

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

type worker struct {
	sync.Mutex

	logger *logging.Logger

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	quitCh    chan struct{}
	initCh    chan struct{}

	runtimeID    signature.PublicKey
	workerHost   host.Host
	localStorage *host.LocalStorage
	grpc         *grpc.Server

	registration  *registration.Registration
	enclaveStatus *api.SignedInitResponse
	backend       api.Backend

	enabled     bool
	mayGenerate bool
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
			return nil, errMalformedResponse
		}

		return resp.Response, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-w.stopCh:
		return nil, fmt.Errorf("worker/keymanager: terminating")
	}
}

func (w *worker) onProcessStart(proto *protocol.Protocol, tee *node.CapabilityTEE) error {
	// TODO: A more natural place to do this is probably on node
	// registration, or better yet periodically based on the BFT
	// component.

	// Initialize the key manager.
	type InitRequest struct {
		Checksum    []byte `codec:"checksum"`
		Policy      []byte `codec:"policy"`
		MayGenerate bool   `codec:"may_generate"`
	}
	type InitCall struct { // nolint: maligned
		Method string      `codec:"method"`
		Args   InitRequest `codec:"args"`
	}

	// Query the BFT component for the policy, checksum, peers (as available).
	status, err := w.backend.GetStatus(w.ctx, w.runtimeID)
	if err != nil {
		if err != api.ErrNoSuchKeyManager {
			w.logger.Error("failed to query key manger status",
				"err", err,
				"id", w.runtimeID,
			)
			return err
		}
		status = &api.Status{}
	}

	var policy []byte
	if status.Policy != nil {
		policy = cbor.Marshal(status.Policy)
	}

	call := InitCall{
		Method: "init",
		Args: InitRequest{
			Checksum:    cbor.FixSliceForSerde(status.Checksum),
			Policy:      cbor.FixSliceForSerde(policy),
			MayGenerate: w.mayGenerate,
		},
	}
	req := &protocol.Body{
		WorkerLocalRPCCallRequest: &protocol.WorkerLocalRPCCallRequest{
			Request:   cbor.Marshal(&call),
			StateRoot: emptyRoot,
		},
	}

	response, err := proto.Call(w.ctx, req)
	if err != nil {
		w.logger.Error("failed to initialize enclave",
			"err", err,
		)
		return err
	}
	if response.Error != nil {
		w.logger.Error("error initializing enclave",
			"err", response.Error.Message,
		)
		return fmt.Errorf("worker/keymanager: error initializing enclave: %s", response.Error.Message)
	}

	resp := response.WorkerLocalRPCCallResponse
	if resp == nil {
		w.logger.Error("malformed response initializing enclave",
			"response", response,
		)
		return errMalformedResponse
	}

	innerResp, err := extractMessageResponsePayload(resp.Response)
	if err != nil {
		w.logger.Error("failed to extract rpc response payload",
			"err", err,
		)
		return errors.Wrap(err, "worker/keymanager: failed to extract rpc response payload")
	}

	var signedInitResp api.SignedInitResponse
	if err = cbor.Unmarshal(innerResp, &signedInitResp); err != nil {
		w.logger.Error("failed to parse response initializing enclave",
			"err", err,
			"response", innerResp,
		)
		return errors.Wrap(err, "worker/keymanager: failed to parse response initializing enclave")
	}

	// Validate the signature.
	if tee != nil {
		var signingKey signature.PublicKey

		switch tee.Hardware {
		case node.TEEHardwareInvalid:
			signingKey = api.TestPublicKey
		case node.TEEHardwareIntelSGX:
			signingKey = tee.RAK
		default:
			return fmt.Errorf("worker/keymanager: unknown TEE hardware: %v", tee.Hardware)
		}

		if err = signedInitResp.Verify(signingKey); err != nil {
			return errors.Wrap(err, "worker/keymanager: failed to validate initialziation response signature")
		}
	}

	if !signedInitResp.InitResponse.IsSecure {
		w.logger.Warn("Key manager enclave build is INSECURE")
	}

	w.logger.Info("Key manager initialized",
		"checksum", hex.EncodeToString(signedInitResp.InitResponse.Checksum),
	)

	// Cache the key manager enclave status.
	w.Lock()
	defer w.Unlock()

	w.enclaveStatus = &signedInitResp

	return nil
}

func extractMessageResponsePayload(raw []byte) ([]byte, error) {
	// See: runtime/src/rpc/types.rs
	type MessageResponseBody struct {
		Success interface{}
		Error   *string
	}
	type MessageResponse struct {
		Response *struct {
			Body MessageResponseBody `codec:"body"`
		}
	}

	var msg MessageResponse
	if err := cbor.Unmarshal(raw, &msg); err != nil {
		return nil, errors.Wrap(err, "malformed message envelope")
	}

	if msg.Response == nil {
		return nil, fmt.Errorf("message is not a response: '%s'", hex.EncodeToString(raw))
	}

	switch {
	case msg.Response.Body.Success != nil:
	case msg.Response.Body.Error != nil:
		return nil, fmt.Errorf("rpc failure: '%s'", *msg.Response.Body.Error)
	default:
		return nil, fmt.Errorf("unknown rpc response status: '%s'", hex.EncodeToString(raw))
	}

	return cbor.Marshal(msg.Response.Body.Success), nil
}

func (w *worker) onNodeRegistration(n *node.Node) error {
	tee, err := w.workerHost.WaitForCapabilityTEE(w.ctx)
	if err != nil {
		w.logger.Error("failed to obtain CapabilityTEE",
			"err", err,
		)
		return err
	}

	// Pull out the enclave status to be appended to the node registration.
	w.Lock()
	enclaveStatus := w.enclaveStatus
	w.Unlock()
	if enclaveStatus == nil {
		w.logger.Error("enclave not initialized")
		return fmt.Errorf("worker/keymanager: enclave not initialized")
	}

	rtVersion, err := w.workerHost.WaitForRuntimeVersion(w.ctx)
	if err != nil {
		w.logger.Error("failed to obtain RuntimeVersion",
			"err", err,
			"runtime", w.runtimeID,
		)
	}

	// Add the key manager runtime to the node descriptor.  Done here instead
	// of in the registration's generic handler since the registration handler
	// only knows about normal runtimes.
	rtDesc := &node.Runtime{
		ID:        w.runtimeID,
		Version:   *rtVersion,
		ExtraInfo: cbor.Marshal(enclaveStatus),
	}
	rtDesc.Capabilities.TEE = tee
	n.Runtimes = append(n.Runtimes, rtDesc)

	n.AddRoles(node.RoleKeyManager)

	return nil
}

// New constructs a new key manager worker.
func New(dataDir string, ias *ias.IAS, grpc *grpc.Server, r *registration.Registration, workerCommonCfg *workerCommon.Config, backend api.Backend) (service.BackgroundService, bool, error) {
	var teeHardware node.TEEHardware
	s := viper.GetString(CfgTEEHardware)
	if err := teeHardware.FromString(s); err != nil {
		return nil, false, fmt.Errorf("invalid TEE hardware: %s", s)
	}

	workerRuntimeLoaderBinary := viper.GetString(CfgRuntimeLoader)
	runtimeBinary := viper.GetString(CfgRuntimeBinary)

	ctx, cancelFn := context.WithCancel(context.Background())

	w := &worker{
		logger:       logging.GetLogger("worker/keymanager"),
		ctx:          ctx,
		cancelCtx:    cancelFn,
		stopCh:       make(chan struct{}),
		quitCh:       make(chan struct{}),
		initCh:       make(chan struct{}),
		grpc:         grpc,
		registration: r,
		backend:      backend,
		enabled:      viper.GetBool(CfgEnabled),
		mayGenerate:  viper.GetBool(CfgMayGenerate),
	}

	if w.enabled {
		if err := w.runtimeID.UnmarshalHex(viper.GetString(CfgRuntimeID)); err != nil {
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

		hostCfg := &host.Config{
			Role:           node.RoleKeyManager,
			ID:             w.runtimeID,
			WorkerBinary:   workerRuntimeLoaderBinary,
			RuntimeBinary:  runtimeBinary,
			TEEHardware:    teeHardware,
			IAS:            ias,
			MessageHandler: newHostHandler(w),
			OnProcessStart: w.onProcessStart,
		}

		if w.workerHost, err = host.NewHost(hostCfg); err != nil {
			return nil, false, errors.Wrap(err, "worker/keymanager: failed to create worker host")
		}

		newEnclaveRPCGRPCServer(w)
	}

	return w, w.enabled, nil
}

func init() {
	emptyRoot.Empty()

	Flags.Bool(CfgEnabled, false, "Enable key manager worker")

	Flags.String(CfgTEEHardware, "", "TEE hardware to use for the key manager")
	Flags.String(CfgRuntimeLoader, "", "Path to key manager worker process binary")
	Flags.String(CfgRuntimeBinary, "", "Path to key manager runtime binary")
	Flags.String(CfgRuntimeID, "", "Key manager Runtime ID")
	Flags.Bool(CfgMayGenerate, false, "Key manager may generate new master secret")

	_ = viper.BindPFlags(Flags)
}
