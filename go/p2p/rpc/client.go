package rpc

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	commonErrors "github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/workerpool"
)

const (
	// RequestWriteDeadline is the maximum amount of time that can be spent on writing a request.
	RequestWriteDeadline = 5 * time.Second
	// RequestReadDeadline is the maximum amount of time that can be spent on reading a request.
	RequestReadDeadline = 5 * time.Second
	// DefaultCallRetryInterval is the default call retry interval for calls which explicitly enable
	// retries by setting the WithMaxRetries option to a non-zero value. It can be overridden by
	// using the WithRetryInterval call option.
	DefaultCallRetryInterval = 1 * time.Second
	// DefaultParallelRequests is the default number of parallel requests that can be made
	// when calling multiple peers.
	DefaultParallelRequests = 5
)

// PeerFeedback is an interface for providing deferred peer feedback after an outcome is known.
type PeerFeedback interface {
	// RecordSuccess records a successful protocol interaction with the given peer.
	RecordSuccess()

	// RecordFailure records an unsuccessful protocol interaction with the given peer.
	RecordFailure()

	// RecordBadPeer records a malicious protocol interaction with the given peer.
	//
	// The peer will be ignored during peer selection.
	RecordBadPeer()

	// PeerID returns the ID of the peer.
	PeerID() core.PeerID
}

type peerFeedback struct {
	client  *client
	peerID  core.PeerID
	latency time.Duration
}

func (pf *peerFeedback) RecordSuccess() {
	pf.client.recordSuccess(pf.peerID, pf.latency)
}

func (pf *peerFeedback) RecordFailure() {
	pf.client.recordFailure(pf.peerID, pf.latency)
}

func (pf *peerFeedback) RecordBadPeer() {
	pf.client.recordBadPeer(pf.peerID)
}

func (pf *peerFeedback) PeerID() core.PeerID {
	return pf.peerID
}

type nopPeerFeedback struct{}

func (pf *nopPeerFeedback) RecordSuccess() {
}

func (pf *nopPeerFeedback) RecordFailure() {
}

func (pf *nopPeerFeedback) RecordBadPeer() {
}

func (pf *nopPeerFeedback) PeerID() core.PeerID {
	return ""
}

// NewNopPeerFeedback creates a no-op peer feedback instance.
func NewNopPeerFeedback() PeerFeedback {
	return &nopPeerFeedback{}
}

// ValidationFunc is a call response validation function.
type ValidationFunc func(pf PeerFeedback) error

// CallOptions are per-call options.
type CallOptions struct {
	maxPeerResponseTime time.Duration
	retryInterval       time.Duration
	maxRetries          uint64
	validationFn        ValidationFunc
}

// NewCallOptions creates options using default and given values.
func NewCallOptions(opts ...CallOption) *CallOptions {
	co := CallOptions{
		maxPeerResponseTime: RequestReadDeadline,
		retryInterval:       DefaultCallRetryInterval,
	}
	for _, opt := range opts {
		opt(&co)
	}
	return &co
}

// CallOption is a per-call option setter.
type CallOption func(opts *CallOptions)

// WithMaxPeerResponseTime configures the maximum response time for a peer.
func WithMaxPeerResponseTime(d time.Duration) CallOption {
	return func(opts *CallOptions) {
		opts.maxPeerResponseTime = d
	}
}

// WithMaxRetries configures the maximum number of retries to use for the call.
func WithMaxRetries(maxRetries uint64) CallOption {
	return func(opts *CallOptions) {
		opts.maxRetries = maxRetries
	}
}

// WithRetryInterval configures the retry interval to use for the call.
func WithRetryInterval(retryInterval time.Duration) CallOption {
	return func(opts *CallOptions) {
		opts.retryInterval = retryInterval
	}
}

// WithValidationFn configures the response validation function to use for the call.
//
// When the function is called, the decoded response value will be set.
func WithValidationFn(fn ValidationFunc) CallOption {
	return func(opts *CallOptions) {
		opts.validationFn = fn
	}
}

// AggregateFunc returns a result aggregation function.
//
// The function is passed the response and PeerFeedback instance. If the function returns true, the
// client will continue to call other peers. If it returns false, processing will stop.
type AggregateFunc func(rsp interface{}, pf PeerFeedback) bool

// CallMultiOptions are per-multicall options.
type CallMultiOptions struct {
	maxPeerResponseTime time.Duration
	maxParallelRequests uint
	aggregateFn         AggregateFunc
}

// NewCallMultiOptions creates options using default and given values.
func NewCallMultiOptions(opts ...CallMultiOption) *CallMultiOptions {
	co := CallMultiOptions{
		maxPeerResponseTime: RequestReadDeadline,
		maxParallelRequests: DefaultParallelRequests,
	}
	for _, opt := range opts {
		opt(&co)
	}
	return &co
}

// CallMultiOption is a per-multicall option setter.
type CallMultiOption func(opts *CallMultiOptions)

// WithMaxPeerResponseTimeMulti configures the maximum response time for a peer.
func WithMaxPeerResponseTimeMulti(d time.Duration) CallMultiOption {
	return func(opts *CallMultiOptions) {
		opts.maxPeerResponseTime = d
	}
}

// WithMaxParallelRequests configures the maximum number of parallel requests to make.
func WithMaxParallelRequests(n uint) CallMultiOption {
	return func(opts *CallMultiOptions) {
		opts.maxParallelRequests = n
	}
}

// WithAggregateFn configures the response aggregation function to use.
func WithAggregateFn(fn AggregateFunc) CallMultiOption {
	return func(opts *CallMultiOptions) {
		opts.aggregateFn = fn
	}
}

// ClientListener is an interface for an object wishing to receive notifications from the client.
type ClientListener interface {
	// RecordSuccess is called on a successful protocol interaction with a peer.
	RecordSuccess(peerID core.PeerID, latency time.Duration)

	// RecordFailure is called on an unsuccessful protocol interaction with a peer.
	RecordFailure(peerID core.PeerID, latency time.Duration)

	// RecordBadPeer is called when a malicious protocol interaction with a peer is detected.
	RecordBadPeer(peerID core.PeerID)
}

// Client is an RPC client for a given protocol.
type Client interface {
	// Call attempts to route the given RPC method call to the given peer. It's up to the caller
	// to provide only connected peers that support the protocol.
	//
	// On success it returns a PeerFeedback instance that should be used by the caller to provide
	// deferred feedback on whether the peer is any good or not. This will help guide later choices
	// when routing calls.
	Call(
		ctx context.Context,
		peer core.PeerID,
		method string,
		body, rsp interface{},
		opts ...CallOption,
	) (PeerFeedback, error)

	// CallOne attempts to route the given RPC method call to one of the peers in the list in
	// a sequential order. It's up to the caller to prioritize peers and to provide only
	// connected peers that support the protocol.
	//
	// On success it returns a PeerFeedback instance that should be used by the caller to provide
	// deferred feedback on whether the peer is any good or not. This will help guide later choices
	// when routing calls.
	CallOne(
		ctx context.Context,
		peers []core.PeerID,
		method string,
		body, rsp interface{},
		opts ...CallOption,
	) (PeerFeedback, error)

	// CallMulti routes the given RPC method call to multiple (possibly all) peers in the list in
	// a sequential order. It's up to the caller to prioritize peers and use only peers that support
	// the protocol.
	//
	// It returns all successfully retrieved results and their corresponding PeerFeedback instances.
	CallMulti(
		ctx context.Context,
		peers []core.PeerID,
		method string,
		body, rspTyp interface{},
		opts ...CallMultiOption,
	) ([]interface{}, []PeerFeedback, error)

	// Close closes all connections to the given peer.
	Close(peerID core.PeerID) error

	// CloseIdle closes all connections to the given peer that have no open streams.
	CloseIdle(peerID core.PeerID) error

	// RegisterListener subscribes the listener to the client notification events.
	// If the listener is already registered this is a noop operation.
	RegisterListener(l ClientListener)

	// UnregisterListener unsubscribes the listener from the client notification events.
	// If the listener is not registered this is a noop operation.
	UnregisterListener(l ClientListener)
}

type client struct {
	host       core.Host
	protocolID protocol.ID

	listeners struct {
		sync.RWMutex
		m map[ClientListener]struct{}
	}

	logger *logging.Logger
}

// Implements Client.
func (c *client) Call(
	ctx context.Context,
	peer core.PeerID,
	method string,
	body, rsp interface{},
	opts ...CallOption,
) (PeerFeedback, error) {
	return c.CallOne(ctx, []core.PeerID{peer}, method, body, rsp, opts...)
}

// Implements Client.
func (c *client) CallOne(
	ctx context.Context,
	peers []core.PeerID,
	method string,
	body, rsp interface{},
	opts ...CallOption,
) (PeerFeedback, error) {
	c.logger.Debug("call", "method", method)

	if len(peers) == 0 {
		return nil, fmt.Errorf("no peers given to service the request")
	}

	co := NewCallOptions(opts...)

	// Prepare the request.
	request := Request{
		Method: method,
		Body:   cbor.Marshal(body),
	}

	var pf PeerFeedback
	tryPeers := func() error {
		// Iterate through the list of peers and attempt to execute the request.
		for _, peer := range peers {
			c.logger.Debug("trying peer",
				"method", method,
				"peer_id", peer,
			)

			var err error
			pf, err = c.timeCall(ctx, peer, &request, rsp, co.maxPeerResponseTime)
			if err != nil {
				continue
			}
			if co.validationFn != nil {
				err := co.validationFn(pf)
				if err != nil {
					c.logger.Debug("failed to validate peer response",
						"method", method,
						"peer_id", peer,
						"err", err,
					)
					continue
				}
			}
			return nil
		}

		// No peers could be reached to service this request.
		c.logger.Debug("no peers could be reached to service request",
			"method", method,
		)

		return fmt.Errorf("call failed on all peers")
	}

	err := retryFn(ctx, tryPeers, co.maxRetries, co.retryInterval)

	return pf, err
}

// Implements Client.
func (c *client) CallMulti(
	ctx context.Context,
	peers []core.PeerID,
	method string,
	body, rspTyp interface{},
	opts ...CallMultiOption,
) ([]interface{}, []PeerFeedback, error) {
	c.logger.Debug("call multiple", "method", method)

	co := NewCallMultiOptions(opts...)

	// Prepare the request.
	request := Request{
		Method: method,
		Body:   cbor.Marshal(body),
	}

	// Create a worker pool.
	pool := workerpool.New("p2p/rpc")
	pool.Resize(co.maxParallelRequests)
	defer pool.Stop()

	// Create a subcontext so we abort further requests if we are done early.
	peerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Requests results from peers.
	type result struct {
		rsp interface{}
		pf  PeerFeedback
		err error
	}

	// Prepare a non-blocking channel for workers to push their results.
	resultCh := make(chan result, len(peers))

	for _, peer := range peers {
		pool.Submit(func() {
			// Abort early in case we are done.
			select {
			case <-peerCtx.Done():
				return
			default:
			}

			rsp := reflect.New(reflect.TypeOf(rspTyp)).Interface()
			pf, err := c.timeCall(peerCtx, peer, &request, rsp, co.maxPeerResponseTime)

			resultCh <- result{rsp, pf, err}
		})
	}

	// Gather results.
	var (
		rsps []interface{}
		pfs  []PeerFeedback
	)

loop:
	for i := 0; i < len(peers); i++ {
		select {
		case result := <-resultCh:
			// Ignore failed results.
			if result.err != nil {
				break
			}

			rsps = append(rsps, result.rsp)
			pfs = append(pfs, result.pf)

			if co.aggregateFn != nil {
				if !co.aggregateFn(result.rsp, result.pf) {
					break loop
				}
			}

		case <-peerCtx.Done():
			break loop
		}
	}

	c.logger.Debug("received responses from peers",
		"method", method,
		"num_peers", len(rsps),
	)

	return rsps, pfs, nil
}

func (c *client) timeCall(
	ctx context.Context,
	peerID core.PeerID,
	request *Request,
	rsp interface{},
	maxPeerResponseTime time.Duration,
) (PeerFeedback, error) {
	start := time.Now()
	err := c.call(ctx, peerID, request, rsp, maxPeerResponseTime)
	latency := time.Since(start)

	if err != nil {
		// If the caller canceled the context we should not degrade the peer.
		if !commonErrors.Is(err, context.Canceled) {
			c.recordFailure(peerID, latency)
		}

		c.logger.Debug("failed to call method",
			"err", err,
			"method", request.Method,
			"peer_id", peerID,
		)
	}

	return &peerFeedback{
		client:  c,
		peerID:  peerID,
		latency: latency,
	}, err
}

func (c *client) call(
	ctx context.Context,
	peerID core.PeerID,
	request *Request,
	rsp interface{},
	maxPeerResponseTime time.Duration,
) error {
	// Attempt to open stream to the given peer.
	stream, err := c.host.NewStream(
		ctx,
		peerID,
		c.protocolID,
	)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer func() {
		if err = stream.Close(); err != nil {
			c.logger.Debug("failed to close stream",
				"err", err,
			)
		}
	}()

	codec := cbor.NewMessageCodec(stream, codecModuleName)

	// Send request.
	_ = stream.SetWriteDeadline(time.Now().Add(RequestWriteDeadline))
	if err = codec.Write(request); err != nil {
		c.logger.Debug("failed to send request",
			"err", err,
			"peer_id", peerID,
		)
		return fmt.Errorf("failed to send request: %w", err)
	}
	_ = stream.SetWriteDeadline(time.Time{})

	// Read response.
	// TODO: Add required minimum speed.
	var rawRsp Response
	_ = stream.SetReadDeadline(time.Now().Add(maxPeerResponseTime))
	if err = codec.Read(&rawRsp); err != nil {
		c.logger.Debug("failed to read response",
			"err", err,
			"peer_id", peerID,
		)
		return fmt.Errorf("failed to read response: %w", err)
	}
	_ = stream.SetWriteDeadline(time.Time{})

	// Decode response.
	if rawRsp.Error != nil {
		return commonErrors.FromCode(rawRsp.Error.Module, rawRsp.Error.Code, rawRsp.Error.Message)
	}

	if rsp != nil {
		return cbor.Unmarshal(rawRsp.Ok, rsp)
	}
	return nil
}

// Implements Client.
func (c *client) Close(peerID core.PeerID) error {
	var errs error
	for _, conn := range c.host.Network().ConnsToPeer(peerID) {
		err := conn.Close()
		errs = errors.Join(errs, err)
	}
	return errs
}

// Implements Client.
func (c *client) CloseIdle(peerID core.PeerID) error {
	var errs error
	for _, conn := range c.host.Network().ConnsToPeer(peerID) {
		if len(conn.GetStreams()) > 0 {
			continue
		}
		err := conn.Close()
		errs = errors.Join(errs, err)
	}
	return errs
}

// Implements Client.
func (c *client) RegisterListener(l ClientListener) {
	c.listeners.Lock()
	defer c.listeners.Unlock()

	c.listeners.m[l] = struct{}{}
}

// Implements Client.
func (c *client) UnregisterListener(l ClientListener) {
	c.listeners.Lock()
	defer c.listeners.Unlock()

	delete(c.listeners.m, l)
}

func (c *client) recordSuccess(peerID core.PeerID, latency time.Duration) {
	c.listeners.RLock()
	defer c.listeners.RUnlock()

	for l := range c.listeners.m {
		l.RecordSuccess(peerID, latency)
	}
}

func (c *client) recordFailure(peerID core.PeerID, latency time.Duration) {
	c.listeners.RLock()
	defer c.listeners.RUnlock()

	for l := range c.listeners.m {
		l.RecordFailure(peerID, latency)
	}
}

func (c *client) recordBadPeer(peerID core.PeerID) {
	c.listeners.RLock()
	defer c.listeners.RUnlock()

	for l := range c.listeners.m {
		l.RecordBadPeer(peerID)
	}
}

func retryFn(ctx context.Context, fn func() error, maxRetries uint64, retryInterval time.Duration) error {
	if maxRetries == 0 {
		return fn()
	}

	retry := backoff.WithMaxRetries(backoff.NewConstantBackOff(retryInterval), maxRetries)
	return backoff.Retry(fn, backoff.WithContext(retry, ctx))
}

// NewClient creates a new RPC client for the given protocol.
func NewClient(h host.Host, p protocol.ID) Client {
	if h == nil {
		// No P2P service, use the no-op client.
		return &nopClient{}
	}

	return &client{
		host:       h,
		protocolID: p,
		listeners: struct {
			sync.RWMutex
			m map[ClientListener]struct{}
		}{
			m: make(map[ClientListener]struct{}),
		},
		logger: logging.GetLogger("p2p/rpc/client").With("protocol", p),
	}
}
