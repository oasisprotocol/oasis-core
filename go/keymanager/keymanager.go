// Package keymanager implements the key manager service.
package keymanager

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/ias"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/common/enclaverpc"
	"github.com/oasislabs/ekiden/go/worker/common/host"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

const (
	rpcCallTimeout       = 5 * time.Second
	storageCommitTimeout = 1 * time.Second

	stateRootFilename = "keymanager_state_root.json"
)

// request is an internal request for a call to the key manager
// runtime. We use an internal worker to prevent multiple requests
// from being made in parallel, leading to state root corruption.
type request struct {
	ctx  context.Context
	data []byte
	ch   chan<- interface{}
}

// KeyManager is the key manager service.
type KeyManager struct {
	enabled bool

	workerHost host.Host
	grpc       *grpc.Server
	stopCh     chan struct{}
	quitCh     chan struct{}
	requestCh  chan *request

	localStorage *host.LocalStorage

	storage       storage.Backend
	stateRoot     hash.Hash
	stateRootPath string

	// XXX: Change once we automatically discover the key manager for each runtime.
	client *enclaverpc.Client

	logger *logging.Logger
}

// Name returns the service name.
func (k *KeyManager) Name() string {
	return "key manager"
}

// Start starts the service.
func (k *KeyManager) Start() error {
	if !k.enabled {
		k.logger.Info("not starting key manager as it is disabled")

		return nil
	}

	k.logger.Info("starting key manager service")

	// Start key manager gRPC server.
	if err := k.grpc.Start(); err != nil {
		return err
	}

	// Start worker host.
	if err := k.workerHost.Start(); err != nil {
		return err
	}

	// Start request processor.
	go k.worker()

	return nil
}

// Stop halts the service.
func (k *KeyManager) Stop() {
	if !k.enabled {
		close(k.quitCh)
		return
	}

	k.logger.Info("stopping key manager service")

	k.grpc.Stop()
	k.workerHost.Stop()
	if k.localStorage != nil {
		k.localStorage.Stop()
	}
	close(k.stopCh)
}

// Quit returns a channel that will be closed when the service terminates.
func (k *KeyManager) Quit() <-chan struct{} {
	return k.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (k *KeyManager) Cleanup() {
}

func (k *KeyManager) loadStateRoot() error {
	r, err := ioutil.ReadFile(k.stateRootPath)
	if err != nil {
		// If the file does not exist, start with an empty root.
		if os.IsNotExist(err) {
			k.stateRoot.Empty()

			k.logger.Info("state root file does not exist, starting with empty",
				"root", k.stateRoot.String(),
			)
			return nil
		}
		return err
	}

	var root hash.Hash
	if err := json.Unmarshal(r, &root); err != nil {
		k.logger.Error("corrupted state root file",
			"err", err,
			"data", string(r),
		)
		return err
	}

	k.stateRoot = root

	k.logger.Info("loaded state root",
		"root", k.stateRoot.String(),
	)
	return nil
}

func (k *KeyManager) commitStateRoot(ctx context.Context, storageInserts []storage.Value, root hash.Hash) error {
	ctx, cancel := context.WithTimeout(ctx, storageCommitTimeout)
	defer cancel()

	<-k.storage.Initialized()
	if err := k.storage.InsertBatch(ctx, storageInserts, storage.InsertOptions{}); err != nil {
		k.logger.Error("failed to commit state to storage",
			"err", err,
		)
		return err
	}

	r := json.Marshal(root)
	if err := ioutil.WriteFile(k.stateRootPath, r, 0600); err != nil {
		k.logger.Error("failed to persist state root",
			"root", root.String(),
			"err", err,
		)
		return err
	}

	k.stateRoot = root
	return nil
}

func (k *KeyManager) worker() {
	// Wait for the gRPC server and worker to terminate.
	go func() {
		defer close(k.quitCh)

		<-k.workerHost.Quit()
		<-k.grpc.Quit()
	}()

	for {
		select {
		case <-k.stopCh:
			return
		case callRq := <-k.requestCh:
			// Process a request.
			rq := &protocol.Body{
				WorkerRPCCallRequest: &protocol.WorkerRPCCallRequest{
					Request:   callRq.data,
					StateRoot: k.stateRoot,
				},
			}

			ch, err := k.workerHost.MakeRequest(callRq.ctx, rq)
			if err != nil {
				k.logger.Error("error while sending RPC call to worker host",
					"err", err,
				)
				callRq.ch <- errors.New("keymanager: error while sending RPC call to worker host")
				close(callRq.ch)
				break
			}

			select {
			case response := <-ch:
				if response == nil {
					k.logger.Error("worker channel closed during RPC call")
					callRq.ch <- errors.New("keymanager: worker channel closed during RPC call")
					break
				}

				if response.Error != nil {
					callRq.ch <- fmt.Errorf("keymanager: error from runtime: %s", response.Error.Message)
					break
				}

				rsp := response.WorkerRPCCallResponse
				if rsp == nil {
					k.logger.Error("malformed response from worker",
						"response", response,
					)
					callRq.ch <- errors.New("keymanager: malformed response from worker")
					break
				}

				// Commit new state root.
				if err = k.commitStateRoot(callRq.ctx, rsp.StorageInserts, rsp.NewStateRoot); err != nil {
					callRq.ch <- err
					break
				}

				callRq.ch <- rsp.Response
			case <-callRq.ctx.Done():
				callRq.ch <- callRq.ctx.Err()
			case <-k.stopCh:
				callRq.ch <- fmt.Errorf("keymanager: terminating")
				close(callRq.ch)
				return
			}

			close(callRq.ch)
		}
	}
}

// callLocal calls the local key manager runtime via EnclaveRPC.
func (k *KeyManager) callLocal(ctx context.Context, data []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancel()

	rspCh := make(chan interface{}, 1)
	k.requestCh <- &request{ctx: ctx, data: data, ch: rspCh}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case rsp := <-rspCh:
		switch rsp := rsp.(type) {
		case error:
			return nil, rsp
		case []byte:
			return rsp, nil
		default:
			panic("keymanager: invalid response type")
		}
	}
}

// CallRemote calls a runtime-specific key manager via remote EnclaveRPC.
func (k *KeyManager) CallRemote(ctx context.Context, runtimeID signature.PublicKey, data []byte) ([]byte, error) {
	// TODO: Support per-runtime key manager.
	if k.client == nil {
		return nil, errors.New("key manager client not configured")
	}

	return k.client.CallEnclave(ctx, data)
}

func newKeyManager(
	dataDir string,
	enabled bool,
	teeHardware node.TEEHardware,
	workerRuntimeLoaderBinary string,
	runtimeBinary string,
	port uint16,
	ias *ias.IAS,
	identity *identity.Identity,
	storage storage.Backend,
	client *enclaverpc.Client,
) (*KeyManager, error) {
	km := &KeyManager{
		enabled:       enabled,
		quitCh:        make(chan struct{}),
		stopCh:        make(chan struct{}),
		requestCh:     make(chan *request, 10),
		storage:       storage,
		stateRootPath: filepath.Join(dataDir, stateRootFilename),
		client:        client,
		logger:        logging.GetLogger("keymanager"),
	}

	if enabled {
		var err error

		if workerRuntimeLoaderBinary == "" {
			return nil, fmt.Errorf("keymanager: worker runtime loader binary not configured")
		}

		if runtimeBinary == "" {
			return nil, fmt.Errorf("keymanager: runtime binary not configured")
		}

		if err = km.loadStateRoot(); err != nil {
			return nil, err
		}

		// Open the local storage.
		if km.localStorage, err = host.NewLocalStorage(dataDir, "km-local-storage.bolt.db"); err != nil {
			return nil, err
		}

		// Create worker host for the keymanager runtime.
		km.workerHost, err = host.NewSandboxedHost(
			"keymanager",
			workerRuntimeLoaderBinary,
			runtimeBinary,
			make(map[string]host.ProxySpecification),
			teeHardware,
			ias,
			newHostHandler(storage, km.localStorage),
			false,
		)
		if err != nil {
			return nil, err
		}

		// Create gRPC server.
		grpc, err := grpc.NewServerTCP("keymanager", port, identity.TLSCertificate)
		if err != nil {
			return nil, err
		}
		km.grpc = grpc
		newEnclaveRPCGRPCServer(grpc.Server(), km)
	}

	return km, nil
}
