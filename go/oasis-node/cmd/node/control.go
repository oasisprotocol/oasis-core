package node

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
)

var _ control.ControlledNode = (*Node)(nil)

// Implements control.ControlledNode.
func (n *Node) RequestShutdown() (<-chan struct{}, error) {
	if err := n.RegistrationWorker.RequestDeregistration(); err != nil {
		return nil, err
	}
	// This returns only the registration worker's event channel,
	// otherwise the caller (usually the control grpc server) will only
	// get notified once everything is already torn down - perhaps
	// including the server.
	return n.RegistrationWorker.Quit(), nil
}

// Implements control.ControlledNode.
func (n *Node) Ready() <-chan struct{} {
	return n.readyCh
}

// Implements control.ControlledNode.
func (n *Node) GetIdentity() *identity.Identity {
	return n.Identity
}

// Implements control.ControlledNode.
func (n *Node) GetRegistrationStatus(ctx context.Context) (*control.RegistrationStatus, error) {
	return n.RegistrationWorker.GetRegistrationStatus(ctx)
}
