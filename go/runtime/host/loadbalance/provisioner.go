package loadbalance

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
)

type lbProvisioner struct {
	inner        host.Provisioner
	numInstances int
}

// NewProvisioner creates a load-balancing runtime provisioner.
func NewProvisioner(inner host.Provisioner, numInstances int, metricsEnabled bool) host.Provisioner {
	if numInstances < 2 {
		// If there is only a single instance configured just return the inner provisioner.
		return inner
	}

	if metricsEnabled {
		initMetrics()
	}

	return &lbProvisioner{
		inner:        inner,
		numInstances: numInstances,
	}
}

// Implements host.Provisioner.
func (p *lbProvisioner) NewRuntime(cfg host.Config) (host.Runtime, error) {
	if p.numInstances < 2 {
		// This should never happen as the provisioner constructor made sure, but just to be safe.
		return nil, fmt.Errorf("host/loadbalance: number of instances must be at least two")
	}

	// The load-balancer can only be used for the RONL component. For others, do pass-through.
	if cfg.Component.ID() != component.ID_RONL {
		return p.inner.NewRuntime(cfg)
	}

	// Use the inner provisioner to provision multiple runtimes.
	var instances []host.Runtime
	for i := 0; i < p.numInstances; i++ {
		rt, err := p.inner.NewRuntime(cfg)
		if err != nil {
			return nil, fmt.Errorf("host/loadbalance: failed to provision instance %d: %w", i, err)
		}

		instances = append(instances, rt)
	}

	host := NewHost(cfg.ID, instances)

	return host, nil
}

// Implements host.Provisioner.
func (p *lbProvisioner) Name() string {
	return fmt.Sprintf("load-balancer[%d]/%s", p.numInstances, p.inner.Name())
}
