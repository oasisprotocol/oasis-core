package protocol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/logging"
)

// Handler is a protocol message handler.
type Handler interface {
	// Handle given request and return a response.
	Handle(context.Context, *Body) (*Body, error)
}

// Protocol is a host-worker protocol instance.
type Protocol struct {
	sync.Mutex

	conn  net.Conn
	codec *cbor.MessageCodec

	handler         Handler
	pendingRequests map[uint64]chan *Body
	nextRequestID   uint64

	outCh   chan *Message
	closeCh chan struct{}
	quitWg  sync.WaitGroup

	logger *logging.Logger
}

// Close closes the connection.
func (p *Protocol) Close() {
	if err := p.conn.Close(); err != nil {
		p.logger.Error("error while closing connection",
			"err", err,
		)
	}

	p.quitWg.Wait()
}

// Call sends a request to the other side and returns the response or error.
func (p *Protocol) Call(ctx context.Context, body *Body) (*Body, error) {
	respCh, err := p.MakeRequest(ctx, body)
	if err != nil {
		return nil, err
	}

	select {
	case resp, ok := <-respCh:
		if !ok {
			return nil, errors.New("channel closed")
		}

		if resp.Error != nil {
			return nil, errors.New(resp.Error.Message)
		}

		return resp, nil
	case <-ctx.Done():
		return nil, context.Canceled
	}
}

// MakeRequest sends a request to the other side.
func (p *Protocol) MakeRequest(ctx context.Context, body *Body) (<-chan *Body, error) {
	// Create channel for sending the response and grab next request identifier.
	ch := make(chan *Body, 1)

	p.Lock()
	id := p.nextRequestID
	p.nextRequestID++
	p.pendingRequests[id] = ch
	p.Unlock()

	msg := Message{
		ID:          id,
		MessageType: MessageRequest,
		Body:        *body,
	}

	// Queue the message.
	select {
	case p.outCh <- &msg:
	case <-p.closeCh:
		return nil, errors.New("connection closed")
	case <-ctx.Done():
		return nil, context.Canceled
	}

	return ch, nil
}

func (p *Protocol) workerOutgoing() {
	defer p.quitWg.Done()

	for {
		select {
		case msg := <-p.outCh:
			// Outgoing message, send it.
			if err := p.codec.Write(msg); err != nil {
				p.logger.Error("error while sending message",
					"err", err,
				)
			}
		case <-p.closeCh:
			// Connection has terminated.
			return
		}
	}
}

func (p *Protocol) handleMessage(ctx context.Context, message *Message) {
	switch message.MessageType {
	case MessageRequest:
		// Incoming request.
		body, err := p.handler.Handle(ctx, &message.Body)
		if err != nil {
			body = &Body{Error: &Error{Message: err.Error()}}
		}

		msg := Message{
			ID:          message.ID,
			MessageType: MessageResponse,
			Body:        *body,
		}

		select {
		case p.outCh <- &msg:
		case <-ctx.Done():
			p.logger.Debug("request canceled by context")
		}
	case MessageResponse:
		// Response to our request.
		p.Lock()
		respCh, ok := p.pendingRequests[message.ID]
		delete(p.pendingRequests, message.ID)
		p.Unlock()

		if !ok {
			p.logger.Warn("received a response but no request with id is outstanding",
				"id", message.ID,
			)
			break
		}

		respCh <- &message.Body
		close(respCh)
	case MessageKeepAlive:
		// Keep-alive message, ignore it.
	default:
		p.logger.Warn("received a malformed message from worker, ignoring",
			"msg", fmt.Sprintf("%+v", message),
		)
	}
}

func (p *Protocol) workerIncoming() {
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		// Close connection and signal that connection is closed.
		_ = p.conn.Close()
		close(p.closeCh)

		// Cancel all request handlers.
		cancel()

		// Close all pending request channels.
		p.Lock()
		for id, ch := range p.pendingRequests {
			close(ch)
			delete(p.pendingRequests, id)
		}
		p.Unlock()

		p.quitWg.Done()
	}()

	for {
		// Decode incoming messages.
		var message Message
		err := p.codec.Read(&message)
		if err != nil {
			p.logger.Error("error while receiving message from worker",
				"err", err,
			)
			break
		}

		// Handle message in a separate goroutine.
		go p.handleMessage(ctx, &message)
	}
}

// New creates a new protocol instance.
func New(logger *logging.Logger, conn net.Conn, handler Handler) (*Protocol, error) {
	p := &Protocol{
		conn:            conn,
		codec:           cbor.NewMessageCodec(conn),
		handler:         handler,
		pendingRequests: make(map[uint64]chan *Body),
		outCh:           make(chan *Message),
		closeCh:         make(chan struct{}),
		logger:          logger,
	}
	p.quitWg.Add(2)
	go p.workerIncoming()
	go p.workerOutgoing()

	return p, nil
}
