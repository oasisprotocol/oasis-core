// Package mock implements a mock runtime host useful for tests.
package mock

import (
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
)

type mockProvisioner struct{}

// NewProvisioner creates a new mock runtime provisioner useful for tests.
func NewProvisioner() host.Provisioner {
	return &mockProvisioner{}
}

// Implements host.Provisioner.
func (p *mockProvisioner) NewRuntime(cfg host.Config) (host.Runtime, error) {
	return &mockHost{
		runtimeID: cfg.ID,
		notifier:  pubsub.NewBroker(false),
	}, nil
}

// Implements host.Provisioner.
func (p *mockProvisioner) Name() string {
	return "mock"
}
