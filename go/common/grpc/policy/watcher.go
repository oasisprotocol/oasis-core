package policy

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/accessctl"
	"github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/grpc/policy/api"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
)

var _ api.PolicyWatcher = (*policyWatcher)(nil)

type policyWatcher struct {
	policyNotifier *pubsub.Broker
}

func (c *policyWatcher) PolicyUpdated(service grpc.ServiceName, accessPolicies map[common.Namespace]accessctl.Policy) {
	c.policyNotifier.Broadcast(api.ServicePolicies{Service: service, AccessPolicies: accessPolicies})
}

func (c *policyWatcher) WatchPolicies(ctx context.Context) (<-chan api.ServicePolicies, pubsub.ClosableSubscription, error) {
	typedCh := make(chan api.ServicePolicies)
	sub := c.policyNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

// NewPolicyWatcher retruns a new policy watcher.
func NewPolicyWatcher() api.PolicyWatcher {
	return &policyWatcher{
		policyNotifier: pubsub.NewBroker(true),
	}
}
