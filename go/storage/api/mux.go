package api

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

// ErrMuxDontContinue is the error that should be returned by the MuxController function
// when an operation was successful, but the muxer shouldn't continue with other backends and
// should return an overall success.
var ErrMuxDontContinue = errors.New("dontcontinue")

// MuxContinueWithError is an error type that can be returned by the MuxController function
// when an operation failed, but the muxer should continue anyway. The error returned will be
// last one returned by any failed operation.
//
// NOTE: If one backend in the muxer fails and another succeeds, then using this may cause
// the abnormal situation of the muxer returning both a response and an error for the operation.
type MuxContinueWithError struct {
	wrapped error
}

func (e MuxContinueWithError) Error() string {
	if e.wrapped == nil {
		return "<nil>"
	}
	return e.wrapped.Error()
}

func (e MuxContinueWithError) Unwrap() error {
	return e.wrapped
}

// MuxController controls how a mux storage shim steps through its backend list.
//
// If the controller returns an error, the muxer will normally stop iterating through the backend
// list and return the error (with special handling for errors of type MuxContinueWithError and
// ErrMuxDontContinue).
type MuxController func(i int, backend Backend, meth string, resp interface{}, err error) (interface{}, error)

// MuxReadOpFinishEarly is a chainable controller that stops the muxer as soon as a readonly operation is
// successful. It passes through all other operation transparently to the next controller.
func MuxReadOpFinishEarly(next MuxController) MuxController {
	return func(i int, backend Backend, meth string, resp interface{}, err error) (interface{}, error) {
		switch meth {
		case "GetDiff":
			fallthrough
		case "SyncGet":
			fallthrough
		case "SyncGetPrefixes":
			fallthrough
		case "SyncIterate":
			fallthrough
		case "GetCheckpoints":
			fallthrough
		case "GetCheckpointChunk":
			if err == nil {
				return resp, ErrMuxDontContinue
			}
			return nil, &MuxContinueWithError{err}
		default:
			return next(i, backend, meth, resp, err)
		}
	}
}

// MuxIterateIgnoringLocalErrors creates a controller that tells the muxer to continue iterating
// through its backends even if a local one returns an error.
func MuxIterateIgnoringLocalErrors() MuxController {
	return func(i int, backend Backend, meth string, resp interface{}, err error) (interface{}, error) {
		// Non-local errors are propagated as-is and abort processing.
		if _, ok := backend.(LocalBackend); !ok {
			return resp, err
		}

		// Error in a local backend is ignored.
		if err != nil {
			return resp, &MuxContinueWithError{nil}
		}
		return resp, nil
	}
}

// MuxPassthrough is a mux controller that just returns the response and error it gets. Normally, this will
// cause the muxer to stop on error and continue on a response.
func MuxPassthrough(i int, backend Backend, meth string, resp interface{}, err error) (interface{}, error) {
	return resp, err
}

type storageMux struct {
	backends   []Backend
	controller MuxController

	initOnce sync.Once
	initCh   chan struct{}
}

func (s *storageMux) doDouble(meth string, call func(Backend) (interface{}, error)) (interface{}, error) {
	var residual, newErr error
	var lastResp, ctrlResp interface{}
	for i, b := range s.backends {
		resp, err := call(b)
		ctrlResp, newErr = s.controller(i, b, meth, resp, err)
		if ctrlResp != nil {
			lastResp = ctrlResp
		}
		if wrapped, ok := newErr.(*MuxContinueWithError); ok {
			residual = wrapped.Unwrap()
			newErr = nil
		}
		if newErr == ErrMuxDontContinue {
			return lastResp, nil
		}
		if newErr != nil {
			return lastResp, newErr
		}
	}
	return lastResp, residual
}

func (s *storageMux) Apply(ctx context.Context, request *ApplyRequest) ([]*Receipt, error) {
	resp, err := s.doDouble("Apply", func(b Backend) (interface{}, error) {
		return b.Apply(ctx, request)
	})
	var cast []*Receipt
	if resp != nil {
		cast = resp.([]*Receipt)
	}
	return cast, err
}

func (s *storageMux) ApplyBatch(ctx context.Context, request *ApplyBatchRequest) ([]*Receipt, error) {
	resp, err := s.doDouble("ApplyBatch", func(b Backend) (interface{}, error) {
		return b.ApplyBatch(ctx, request)
	})
	var cast []*Receipt
	if resp != nil {
		cast = resp.([]*Receipt)
	}
	return cast, err
}

func (s *storageMux) GetDiff(ctx context.Context, request *GetDiffRequest) (WriteLogIterator, error) {
	resp, err := s.doDouble("GetDiff", func(b Backend) (interface{}, error) {
		return b.GetDiff(ctx, request)
	})
	var cast WriteLogIterator
	if resp != nil {
		cast = resp.(WriteLogIterator)
	}
	return cast, err
}

func (s *storageMux) SyncGet(ctx context.Context, request *GetRequest) (*ProofResponse, error) {
	resp, err := s.doDouble("SyncGet", func(b Backend) (interface{}, error) {
		return b.SyncGet(ctx, request)
	})
	var cast *ProofResponse
	if resp != nil {
		cast = resp.(*ProofResponse)
	}
	return cast, err
}

func (s *storageMux) SyncGetPrefixes(ctx context.Context, request *GetPrefixesRequest) (*ProofResponse, error) {
	resp, err := s.doDouble("SyncGetPrefixes", func(b Backend) (interface{}, error) {
		return b.SyncGetPrefixes(ctx, request)
	})
	var cast *ProofResponse
	if resp != nil {
		cast = resp.(*ProofResponse)
	}
	return cast, err
}

func (s *storageMux) SyncIterate(ctx context.Context, request *IterateRequest) (*ProofResponse, error) {
	resp, err := s.doDouble("SyncIterate", func(b Backend) (interface{}, error) {
		return b.SyncIterate(ctx, request)
	})
	var cast *ProofResponse
	if resp != nil {
		cast = resp.(*ProofResponse)
	}
	return cast, err
}

func (s *storageMux) GetCheckpoints(ctx context.Context, request *checkpoint.GetCheckpointsRequest) ([]*checkpoint.Metadata, error) {
	resp, err := s.doDouble("GetCheckpoints", func(b Backend) (interface{}, error) {
		return b.GetCheckpoints(ctx, request)
	})
	var cast []*checkpoint.Metadata
	if resp != nil {
		cast = resp.([]*checkpoint.Metadata)
	}
	return cast, err
}

func (s *storageMux) GetCheckpointChunk(ctx context.Context, chunk *checkpoint.ChunkMetadata, w io.Writer) error {
	_, err := s.doDouble("GetCheckpointChunk", func(b Backend) (interface{}, error) {
		return nil, b.GetCheckpointChunk(ctx, chunk, w)
	})
	return err
}

func (s *storageMux) Cleanup() {
	for _, b := range s.backends {
		b.Cleanup()
	}
}

func (s *storageMux) Initialized() <-chan struct{} {
	s.initOnce.Do(func() {
		go func() {
			defer close(s.initCh)
			for _, b := range s.backends {
				<-b.Initialized()
			}
		}()
	})
	return s.initCh
}

// NewStorageMux constructs a multiplexer for multiple storage backends. Requests are sent to
// all of them. It is the controller's job to determine on each step if the muxer should continue
// with further backends or not.
//
// Normally, the return values are the last non-nil return of any backend and the last non-nil error
// of any backend, so client code should take care to take into account the otherwise unusual situation
// where both the response and error are valid non-nil values.
func NewStorageMux(controller MuxController, backends ...Backend) Backend {
	return &storageMux{
		backends:   backends,
		controller: controller,
		initCh:     make(chan struct{}),
	}
}
