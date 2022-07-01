package cmd

import (
	"context"
	"fmt"
	"net"
	"net/rpc"
	"sync"

	"github.com/powerman/rpc-codec/jsonrpc2"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

type dbRPCService struct {
	ln net.Listener

	db *Database

	svrCh  chan struct{}
	quitCh chan struct{}
}

func (svc *dbRPCService) Name() string {
	return "protocol_server"
}

func (svc *dbRPCService) Start() error {
	svr := rpc.NewServer()
	if err := svr.Register(svc.db); err != nil {
		return err
	}

	go func() {
		defer close(svc.svrCh)

		var wg sync.WaitGroup
		for {
			conn, err := svc.ln.Accept()
			if err != nil {
				break
			}
			wg.Add(1)

			go func() {
				defer func() {
					_ = conn.Close()
					wg.Done()
				}()

				codec := jsonrpc2.NewServerCodec(conn, svr)
				svr.ServeCodec(codec)
			}()
		}
		wg.Wait()
	}()

	return nil
}

func (svc *dbRPCService) Stop() {
	defer close(svc.quitCh)

	_ = svc.ln.Close()
	<-svc.svrCh
}

func (svc *dbRPCService) Quit() <-chan struct{} {
	return svc.quitCh
}

func (svc *dbRPCService) Cleanup() {}

func newDbRPCService(
	ln net.Listener,
	backend storage.LocalBackend,
) *dbRPCService {
	return &dbRPCService{
		ln: ln,
		db: &Database{
			ctx:   context.Background(),
			inner: backend,
		},
	}
}

type Database struct {
	ctx   context.Context
	inner storage.LocalBackend
}

// RPCRequest should not be asked about, as the author also thinks it is stupid.
type RPCRequest struct {
	Payload []byte `json:"payload"`
}

type RPCResponse struct {
	Payload []byte `json:"payload"`
}

type (
	// ApplyRequest and family are arrays because that's what Rust sends.
	ApplyRequest       []RPCRequest
	GetRequest         []RPCRequest
	GetPrefixesRequest []RPCRequest
	IterateRequest     []RPCRequest
)

type ApplyResponse struct{}

func (db *Database) Apply(request ApplyRequest, response *ApplyResponse) error {
	if l := len(request); l != 1 {
		return fmt.Errorf("Apply: invalid number of requests: %d", l)
	}

	var req storage.ApplyRequest
	if err := cbor.Unmarshal(request[0].Payload, &req); err != nil {
		return fmt.Errorf("Apply: invalid request payload: %w", err)
	}

	err := db.inner.Apply(db.ctx, &req)
	return err
}

func (db *Database) SyncGet(request GetRequest, response *RPCResponse) error {
	if l := len(request); l != 1 {
		return fmt.Errorf("SyncGet: invalid number of requests: %d", l)
	}

	var req storage.GetRequest
	if err := cbor.Unmarshal(request[0].Payload, &req); err != nil {
		return fmt.Errorf("SyncGet: invalid request payload: %w", err)
	}

	resp, err := db.inner.SyncGet(db.ctx, &req)
	if err == nil {
		response.Payload = cbor.Marshal(&resp)
	}
	return err
}

func (db *Database) SyncGetPrefixes(request GetPrefixesRequest, response *RPCResponse) error {
	if l := len(request); l != 1 {
		return fmt.Errorf("SyncGetPrefixes: invalid number of requests: %d", l)
	}

	var req storage.GetPrefixesRequest
	if err := cbor.Unmarshal(request[0].Payload, &req); err != nil {
		return fmt.Errorf("SyncGetPrefixes: invalid request payload: %w", err)
	}

	resp, err := db.inner.SyncGetPrefixes(db.ctx, &req)
	if err == nil {
		response.Payload = cbor.Marshal(&resp)
	}
	return err
}

func (db *Database) SyncIterate(request IterateRequest, response *RPCResponse) error {
	if l := len(request); l != 1 {
		return fmt.Errorf("SyncIterate: invalid number of requests: %d", l)
	}

	var req storage.IterateRequest
	if err := cbor.Unmarshal(request[0].Payload, &req); err != nil {
		return fmt.Errorf("SyncIterate: invalid request payload: %w", err)
	}

	resp, err := db.inner.SyncIterate(db.ctx, &req)
	if err == nil {
		response.Payload = cbor.Marshal(&resp)
	}
	return err
}
