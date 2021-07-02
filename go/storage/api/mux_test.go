package api

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type faultyBackend struct {
	LocalBackend

	calledCh chan struct{}
	returnCh chan error
}

func (b *faultyBackend) Apply(ctx context.Context, request *ApplyRequest) ([]*Receipt, error) {
	b.calledCh <- struct{}{}
	if err := <-b.returnCh; err != nil {
		return nil, err
	}
	return []*Receipt{nil}, nil
}

func (b *faultyBackend) SyncGet(ctx context.Context, request *GetRequest) (*ProofResponse, error) {
	b.calledCh <- struct{}{}
	if err := <-b.returnCh; err != nil {
		return nil, err
	}
	return &ProofResponse{}, nil
}

func TestStorageMux(t *testing.T) {
	ctx := context.Background()
	someError := errors.New("error")
	calledCh := make(chan struct{}, 2)
	faulty1 := &faultyBackend{
		calledCh: calledCh,
		returnCh: make(chan error, 1),
	}
	faulty2 := &faultyBackend{
		calledCh: calledCh,
		returnCh: make(chan error, 1),
	}

	mux := NewStorageMux(
		MuxReadOpFinishEarly(MuxIterateIgnoringLocalErrors()),
		faulty1,
		faulty2,
	)

	var (
		applyResp []*Receipt
		getResp   *ProofResponse
		err       error
	)

	// Both need to respond to a write request.
	faulty1.returnCh <- nil
	faulty2.returnCh <- nil
	_, err = mux.Apply(ctx, &ApplyRequest{})
	require.NoError(t, err)
	<-faulty1.calledCh
	<-faulty2.calledCh

	// If the first write fails, the second one should still go through
	// with the controllers we set up.
	faulty1.returnCh <- someError
	faulty2.returnCh <- nil
	applyResp, err = mux.Apply(ctx, &ApplyRequest{})
	require.NoError(t, err)
	require.NotNil(t, applyResp)
	<-faulty1.calledCh
	<-faulty2.calledCh

	// The second one shouldn't be called when the first read request succeeds.
	faulty1.returnCh <- nil
	_, err = mux.SyncGet(ctx, &GetRequest{})
	require.NoError(t, err)
	<-faulty1.calledCh
	select {
	case <-faulty2.calledCh:
		require.FailNow(t, "faulty2 shouldn't be called")
	default:
	}

	// If the first read fails, call the second one too.
	faulty1.returnCh <- someError
	faulty2.returnCh <- nil
	getResp, err = mux.SyncGet(ctx, &GetRequest{})
	require.NoError(t, err, "second read succeeded, so there should be no error")
	require.NotNil(t, getResp)
	<-faulty1.calledCh
	<-faulty2.calledCh

	// Also test early termination, all backends need to succeed.
	mux = NewStorageMux(MuxPassthrough, faulty1, faulty2)
	faulty1.returnCh <- someError
	_, err = mux.Apply(ctx, &ApplyRequest{})
	require.EqualError(t, err, "error")
	<-faulty1.calledCh
	select {
	case <-faulty2.calledCh:
		require.FailNow(t, "faulty2 shouldn't be called")
	default:
	}
}
