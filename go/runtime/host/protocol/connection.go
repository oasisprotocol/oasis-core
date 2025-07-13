// Package protocol implements the Runtime Host Protocol.
package protocol

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
)

const (
	moduleName = "rhp/internal"

	// connWriteTimeout is the connection write timeout.
	connWriteTimeout = 5 * time.Second
	// connReadyTimeout is the timeout while waiting for the connection to be ready while attempting
	// to handle a new request from the runtime.
	connReadyTimeout = 5 * time.Second
)

// ErrNotReady is the error reported when the Runtime Host Protocol is not initialized.
var ErrNotReady = errors.New(moduleName, 1, "rhp: not ready")

// Handler is a protocol message handler interface.
type Handler interface {
	// Handle given request and return a response.
	Handle(ctx context.Context, body *Body) (*Body, error)
}

// Connection is a Runtime Host Protocol connection interface.
type Connection interface {
	// Close closes the connection.
	Close()

	// GetInfo retrieves the runtime information.
	GetInfo() (*RuntimeInfoResponse, error)

	// Call sends a request to the other side and returns the response or error.
	Call(ctx context.Context, body *Body) (*Body, error)

	// InitHost performs initialization in host mode and transitions the connection to Ready state.
	//
	// This method must be called before the host will answer requests.
	//
	// Only one of InitHost/InitGuest can be called otherwise the method may panic.
	//
	// Returns the self-reported runtime version.
	InitHost(ctx context.Context, conn net.Conn, hi *HostInfo) (*version.Version, error)

	// InitGuest performs initialization in guest mode and transitions the connection to Ready
	// state.
	//
	// Only one of InitHost/InitGuest can be called otherwise the method may panic.
	InitGuest(conn net.Conn) error
}

// HostInfo contains the information about the host environment that is sent to the runtime during
// connection initialization.
type HostInfo struct {
	// ConsensusBackend is the name of the consensus backend that is in use for the consensus layer.
	ConsensusBackend string
	// ConsensusProtocolVersion is the consensus protocol version that is in use for the consensus
	// layer.
	ConsensusProtocolVersion version.Version
	// ConsensusChainContext is the consensus layer chain domain separation context.
	ConsensusChainContext string

	// LocalConfig is the node-local runtime configuration.
	//
	// This configuration must not be used in any context which requires determinism across
	// replicated runtime instances.
	LocalConfig map[string]any
}

// Clone returns a copy of the HostInfo structure.
func (hi *HostInfo) Clone() *HostInfo {
	var localConfig map[string]any
	if hi.LocalConfig != nil {
		localConfig = make(map[string]any)
		for k, v := range hi.LocalConfig {
			localConfig[k] = v
		}
	}

	return &HostInfo{
		ConsensusBackend:         hi.ConsensusBackend,
		ConsensusProtocolVersion: hi.ConsensusProtocolVersion,
		ConsensusChainContext:    hi.ConsensusChainContext,
		LocalConfig:              localConfig,
	}
}

// state is the connection state.
type state uint8

const (
	stateUninitialized state = iota
	stateInitializing
	stateReady
	stateClosed
)

func (s state) String() string {
	switch s {
	case stateUninitialized:
		return "uninitialized"
	case stateInitializing:
		return "initializing"
	case stateReady:
		return "ready"
	case stateClosed:
		return "closed"
	default:
		return fmt.Sprintf("[malformed: %d]", s)
	}
}

// validStateTransitions are allowed connection state transitions.
var validStateTransitions = map[state][]state{
	stateUninitialized: {
		stateInitializing,
	},
	stateInitializing: {
		stateReady,
		stateClosed,
	},
	stateReady: {
		stateClosed,
	},
	// No transitions from Closed state.
	stateClosed: {},
}

type connection struct { // nolint: maligned
	sync.RWMutex

	conn  net.Conn
	codec *cbor.MessageCodec

	runtimeID common.Namespace
	handler   Handler

	state           state
	pendingRequests map[uint64]chan<- *Body
	nextRequestID   uint64

	info *RuntimeInfoResponse

	readyCh chan struct{}
	outCh   chan *Message
	closeCh chan struct{}
	quitWg  sync.WaitGroup

	logger *logging.Logger
}

func (c *connection) getState() state {
	c.RLock()
	s := c.state
	c.RUnlock()
	return s
}

// waitReady waits for the connection to become ready for at most connReadyTimeout.
func (c *connection) waitReady(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, connReadyTimeout)
	defer cancel()

	select {
	case <-c.readyCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *connection) setStateLocked(s state) {
	// Validate state transition.
	dests := validStateTransitions[c.state]

	var valid bool
	for _, dest := range dests {
		if dest == s {
			valid = true
			break
		}
	}

	if !valid {
		panic(fmt.Sprintf("invalid state transition: %s -> %s", c.state, s))
	}

	c.state = s
}

// Implements Connection.
func (c *connection) Close() {
	c.Lock()
	if c.state != stateReady && c.state != stateInitializing {
		c.Unlock()
		return
	}

	c.setStateLocked(stateClosed)
	c.Unlock()

	if err := c.conn.Close(); err != nil {
		c.logger.Error("error while closing connection",
			"err", err,
		)
	}

	// Wait for all the connection-handling goroutines to terminate.
	c.quitWg.Wait()
}

// Implements Connection.
func (c *connection) GetInfo() (*RuntimeInfoResponse, error) {
	c.Lock()
	defer c.Unlock()

	if c.info == nil {
		return nil, ErrNotReady
	}
	return c.info, nil
}

// Implements Connection.
func (c *connection) Call(ctx context.Context, body *Body) (*Body, error) {
	if c.getState() != stateReady {
		return nil, ErrNotReady
	}

	b, err := c.call(ctx, body)
	return b, err
}

func (c *connection) call(ctx context.Context, body *Body) (result *Body, err error) {
	start := time.Now()
	defer func() {
		if !metrics.Enabled() {
			return
		}

		rhpLatency.With(prometheus.Labels{"call": body.Type()}).Observe(time.Since(start).Seconds())
		if err != nil {
			rhpCallFailures.With(prometheus.Labels{"call": body.Type()}).Inc()

			// Specifically measure timeouts.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				rhpCallTimeouts.Inc()
			}
		} else {
			rhpCallSuccesses.With(prometheus.Labels{"call": body.Type()}).Inc()
		}
	}()

	// Create channel for sending the response and grab next request identifier.
	respCh := make(chan *Body, 1)

	c.Lock()
	id := c.nextRequestID
	c.nextRequestID++
	c.pendingRequests[id] = respCh
	c.Unlock()

	defer func() {
		c.Lock()
		defer c.Unlock()
		delete(c.pendingRequests, id)
	}()

	msg := Message{
		ID:          id,
		MessageType: MessageRequest,
		Body:        *body,
	}

	// Queue the message.
	if err = c.sendMessage(ctx, &msg); err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	// Await a response.
	resp, err := c.readResponse(ctx, respCh)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *connection) sendMessage(ctx context.Context, msg *Message) error {
	select {
	case c.outCh <- msg:
		return nil
	case <-c.closeCh:
		return fmt.Errorf("connection closed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *connection) readResponse(ctx context.Context, respCh <-chan *Body) (*Body, error) {
	select {
	case resp := <-respCh:
		if resp.Error != nil {
			// Decode error.
			return nil, errors.FromCode(resp.Error.Module, resp.Error.Code, resp.Error.Message)
		}

		return resp, nil
	case <-c.closeCh:
		return nil, fmt.Errorf("failed to read response: %w", fmt.Errorf("connection closed"))
	case <-ctx.Done():
		return nil, fmt.Errorf("failed to read response: %w", ctx.Err())
	}
}

func (c *connection) workerOutgoing() {
	for {
		select {
		case msg := <-c.outCh:
			if err := c.conn.SetWriteDeadline(time.Now().Add(connWriteTimeout)); err != nil {
				c.logger.Error("error setting connection deadline",
					"err", err,
				)
			}
			// Outgoing message, send it.
			if err := c.codec.Write(msg); err != nil {
				c.logger.Error("error while sending message",
					"err", err,
				)
			}
			if err := c.conn.SetWriteDeadline(time.Time{}); err != nil {
				c.logger.Error("error setting connection deadline",
					"err", err,
				)
			}
		case <-c.closeCh:
			// Connection has terminated.
			return
		}
	}
}

func errorToBody(err error) *Body {
	module, code := errors.Code(err)
	return &Body{
		Error: &Error{
			Module:  module,
			Code:    code,
			Message: err.Error(),
		},
	}
}

func newResponseMessage(req *Message, body *Body) *Message {
	return &Message{
		ID:          req.ID,
		MessageType: MessageResponse,
		Body:        *body,
	}
}

func (c *connection) handleMessage(ctx context.Context, message *Message) {
	switch message.MessageType {
	case MessageRequest:
		// Incoming request.
		if err := c.waitReady(ctx); err != nil {
			_ = c.sendMessage(ctx, newResponseMessage(message, errorToBody(ErrNotReady)))
			return
		}

		// Call actual handler.
		body, err := c.handler.Handle(ctx, &message.Body)
		if err != nil {
			body = errorToBody(err)
		}

		// Prepare and send response.
		if err := c.sendMessage(ctx, newResponseMessage(message, body)); err != nil {
			c.logger.Warn("failed to send response message",
				"err", err,
			)
		}
	case MessageResponse:
		// Response to our request.
		c.Lock()
		respCh, ok := c.pendingRequests[message.ID]
		delete(c.pendingRequests, message.ID)
		c.Unlock()

		if !ok {
			c.logger.Warn("received a response but no request with id is outstanding",
				"id", message.ID,
			)
			break
		}

		respCh <- &message.Body
	default:
		c.logger.Warn("received a malformed message from worker, ignoring",
			"message", fmt.Sprintf("%+v", message),
		)
	}
}

func (c *connection) workerIncoming() {
	// Wait for request handlers to finish.
	var wg sync.WaitGroup
	defer wg.Wait()

	// Cancel all request handlers.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defer func() {
		// Close connection and signal that connection is closed.
		_ = c.conn.Close()
		close(c.closeCh)
	}()

	for {
		// Decode incoming messages.
		var message Message
		err := c.codec.Read(&message)
		if err != nil {
			c.logger.Error("error while receiving message from worker",
				"err", err,
			)
			break
		}

		// Handle message in a separate goroutine.
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Ensure each message has its own context which is canceled at the end.
			localCtx, localCancel := context.WithCancel(ctx)
			defer localCancel()

			c.handleMessage(localCtx, &message)
		}()
	}
}

func (c *connection) initConn(conn net.Conn) {
	c.Lock()
	defer c.Unlock()

	if c.state != stateUninitialized {
		panic("rhp: connection already initialized")
	}

	c.conn = conn
	c.codec = cbor.NewMessageCodec(conn, moduleName)

	c.quitWg.Add(2)
	go func() {
		defer c.quitWg.Done()
		c.workerIncoming()
	}()
	go func() {
		defer c.quitWg.Done()
		c.workerOutgoing()
	}()

	// Change protocol state to Initializing so that some of the requests are allowed.
	c.setStateLocked(stateInitializing)
}

// Implements Connection.
func (c *connection) InitGuest(conn net.Conn) error {
	c.initConn(conn)

	// Transition the protocol state to Ready.
	c.Lock()
	c.setStateLocked(stateReady)
	c.Unlock()

	close(c.readyCh)

	return nil
}

// Implements Connection.
func (c *connection) InitHost(ctx context.Context, conn net.Conn, hi *HostInfo) (*version.Version, error) {
	c.initConn(conn)

	// Check Runtime Host Protocol version.
	rsp, err := c.call(ctx, &Body{RuntimeInfoRequest: &RuntimeInfoRequest{
		RuntimeID:                c.runtimeID,
		ConsensusBackend:         hi.ConsensusBackend,
		ConsensusProtocolVersion: hi.ConsensusProtocolVersion,
		ConsensusChainContext:    hi.ConsensusChainContext,
		LocalConfig:              hi.LocalConfig,
	}})
	switch {
	default:
	case err != nil:
		return nil, fmt.Errorf("rhp: error while requesting runtime info: %w", err)
	case rsp.RuntimeInfoResponse == nil:
		c.logger.Error("unexpected response to RuntimeInfoRequest",
			"response", rsp,
		)
		return nil, fmt.Errorf("rhp: unexpected response to RuntimeInfoRequest")
	}

	info := rsp.RuntimeInfoResponse
	if info.ProtocolVersion.Major != version.RuntimeHostProtocol.Major {
		c.logger.Error("runtime has incompatible protocol version",
			"version", info.ProtocolVersion,
			"expected_version", version.RuntimeHostProtocol,
		)
		return nil, fmt.Errorf("rhp: incompatible protocol version (expected: %s got: %s)",
			version.RuntimeHostProtocol,
			info.ProtocolVersion,
		)
	}

	rtVersion := info.RuntimeVersion
	c.logger.Info("runtime host protocol initialized", "runtime_version", rtVersion)

	// Transition the protocol state to Ready.
	c.Lock()
	c.setStateLocked(stateReady)
	c.info = info
	c.Unlock()

	close(c.readyCh)

	return &rtVersion, nil
}

// NewConnection creates a new uninitialized RHP connection.
func NewConnection(logger *logging.Logger, runtimeID common.Namespace, handler Handler) (Connection, error) {
	initMetrics()

	return &connection{
		runtimeID:       runtimeID,
		handler:         handler,
		state:           stateUninitialized,
		pendingRequests: make(map[uint64]chan<- *Body),
		readyCh:         make(chan struct{}),
		outCh:           make(chan *Message),
		closeCh:         make(chan struct{}),
		logger:          logger,
	}, nil
}
