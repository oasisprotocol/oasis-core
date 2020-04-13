package ias

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	ias "github.com/oasislabs/oasis-core/go/ias/api"
	iasProxy "github.com/oasislabs/oasis-core/go/ias/proxy"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

const registryRetryInterval = 2 * time.Second

type registryAuthenticator struct {
	logger *logging.Logger

	cmd *cobra.Command

	enclaves *enclaveStore

	initOnce sync.Once
	initCh   chan struct{}
}

func (auth *registryAuthenticator) VerifyEvidence(ctx context.Context, evidence *ias.Evidence) error {
	<-auth.initCh

	// TODO: This could/should do something clever with respect to verifying
	// the signer, but node registration currently requires attestations for
	// all of the runtimes that the node supports, leading to a chicken/egg
	// situation.
	//
	// Revisit this after we reconsider the node registration process.

	err := auth.enclaves.verifyEvidence(evidence)
	if err != nil {
		auth.logger.Error("rejecting proxy request, invalid runtime",
			"err", err,
			"runtime_id", evidence.RuntimeID,
		)
		return err
	}

	auth.logger.Debug("allowing proxy request, found enclave identity",
		"runtime_id", evidence.RuntimeID,
	)
	return nil
}

func (auth *registryAuthenticator) watchRuntimes(ctx context.Context, conn *grpc.ClientConn) (
	ch <-chan *registry.Runtime,
	sub pubsub.ClosableSubscription,
	err error,
) {
	op := func() error {
		client := registry.NewRegistryClient(conn)

		// Subscribe to runtimes.
		ch, sub, err = client.WatchRuntimes(ctx)
		if err != nil {
			return err
		}

		return nil
	}

	sched := backoff.NewConstantBackOff(registryRetryInterval)
	err = backoff.Retry(op, backoff.WithContext(sched, ctx))
	if err != nil {
		auth.logger.Error("unable to connect to registry",
			"err", err,
		)
	}

	return
}

func (auth *registryAuthenticator) worker(ctx context.Context) {
	waitRuntimes := viper.GetInt(cfgWaitRuntimes)
	if waitRuntimes <= 0 {
		close(auth.initCh)
	}

	// Create a new gRPC connection to an Oasis Node.
	conn, err := cmdGrpc.NewClient(auth.cmd)
	if err != nil {
		auth.logger.Error("unable to dial the Oasis Node",
			"err", err,
		)
		panic(fmt.Errorf("ias: failed to create gRPC client: %w", err))
	}
	defer conn.Close()

RedialLoop:
	for {
		ch, sub, err := auth.watchRuntimes(ctx, conn)
		if err != nil {
			// This can only fail in case the context is cancelled.
			auth.logger.Info("terminating",
				"err", err,
			)
			return
		}
		defer sub.Close()

		// Watch runtime added events in the registry.
		for {
			var runtime *registry.Runtime
			select {
			case runtime = <-ch:
				if runtime == nil {
					auth.logger.Warn("data source stream closed by peer, re-dialing")

					// Close existing subscription and redial.
					sub.Close()
					continue RedialLoop
				}
			case <-ctx.Done():
				return
			}

			var n int
			n, err = auth.enclaves.addRuntime(runtime)
			if err != nil {
				auth.logger.Error("failed to add runtime",
					"err", err,
					"id", runtime.ID,
				)
				continue
			}
			if waitRuntimes > 0 && n == waitRuntimes {
				auth.logger.Info("sufficient runtimes received, starting verification")
				auth.initOnce.Do(func() {
					close(auth.initCh)
				})
			}
		}
	}
}

func newRegistryAuthenticator(ctx context.Context, cmd *cobra.Command) (iasProxy.Authenticator, error) {
	auth := &registryAuthenticator{
		logger:   logging.GetLogger("cmd/ias/proxy/auth/registry"),
		cmd:      cmd,
		enclaves: newEnclaveStore(),
		initCh:   make(chan struct{}),
	}
	go auth.worker(ctx)

	return auth, nil
}
