package node

import "github.com/oasisprotocol/oasis-core/go/worker/registration"

// Assert that the node implements Delegate interface.
var _ registration.Delegate = (*Node)(nil)

// RegistrationStopped implements registration.Delegate.
func (n *Node) RegistrationStopped() {
	n.Stop()
}
