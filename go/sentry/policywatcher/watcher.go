package policywatcher

import (
	"context"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/policy/api"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	sentry "github.com/oasisprotocol/oasis-core/go/sentry/api"
	sentryClient "github.com/oasisprotocol/oasis-core/go/sentry/client"
)

var _ api.PolicyWatcher = (*policyWatcher)(nil)

type policyWatcher struct {
	sync.RWMutex

	ctx context.Context

	sentryAddrs   []node.TLSAddress
	identity      *identity.Identity
	sentryClients []*sentryClient.Client

	logger *logging.Logger
}

func (c *policyWatcher) PolicyUpdated(service grpc.ServiceName, accessPolicies map[common.Namespace]accessctl.Policy) {
	// Spawn a goroutine, so that we don't block the caller.
	go func() {
		c.Lock()
		defer c.Unlock()

		// Notify the sentry nodes of the new policy.
		for idx, addr := range c.sentryAddrs {
			pushPolicies := func() error {
				var client *sentryClient.Client
				var err error

				if c.sentryClients[idx] != nil {
					client = c.sentryClients[idx]
				} else {
					client, err = sentryClient.New(addr, c.identity)
					if err != nil {
						return err
					}
					c.sentryClients[idx] = client
				}

				policies := sentry.ServicePolicies{
					Service:        service,
					AccessPolicies: accessPolicies,
				}

				err = client.UpdatePolicies(c.ctx, policies)
				if err != nil {
					// Try to reconnect on next try in case our certs have rotated.
					c.sentryClients[idx].Close()
					c.sentryClients[idx] = nil
					return err
				}
				return nil
			}

			sched := backoff.WithMaxRetries(backoff.NewConstantBackOff(1*time.Second), 15)
			err := backoff.Retry(pushPolicies, backoff.WithContext(sched, c.ctx))
			if err != nil {
				c.logger.Error("unable to push new policy to sentry node",
					"err", err,
					"sentry_address", addr,
				)
			}
		}
	}()
}

// New retruns a new policy watcher.
func New(ctx context.Context, sentryAddrs []node.TLSAddress, id *identity.Identity) api.PolicyWatcher {
	return &policyWatcher{
		ctx:           ctx,
		sentryAddrs:   sentryAddrs,
		identity:      id,
		sentryClients: make([]*sentryClient.Client, len(sentryAddrs)),
		logger:        logging.GetLogger("sentry/policywatcher"),
	}
}
