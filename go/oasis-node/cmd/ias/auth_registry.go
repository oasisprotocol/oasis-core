package ias

import (
	"context"
	"sync"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/logging"
	ias "github.com/oasislabs/oasis-core/go/ias/api"
	iasProxy "github.com/oasislabs/oasis-core/go/ias/proxy"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

type registryAuthenticator struct {
	logger *logging.Logger

	conn   *grpc.ClientConn
	client registry.Backend

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

func (auth *registryAuthenticator) worker(ctx context.Context) {
	defer auth.conn.Close()

	waitRuntimes := viper.GetInt(cfgWaitRuntimes)
	if waitRuntimes <= 0 {
		close(auth.initCh)
	}

	ch, sub, err := auth.client.WatchRuntimes(ctx)
	if err != nil {
		auth.logger.Error("failed to start the WatchRuntimes stream",
			"err", err,
		)
		panic("unable to watch runtimes")
	}
	defer sub.Close()

	for {
		var runtime *registry.Runtime
		select {
		case runtime = <-ch:
			if runtime == nil {
				auth.logger.Error("data source stream closed by peer")
				panic("data source disappeared")
			}
		case <-ctx.Done():
			return
		}

		n, err := auth.enclaves.addRuntime(runtime)
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

func newRegistryAuthenticator(ctx context.Context, cmd *cobra.Command) (iasProxy.Authenticator, error) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		return nil, errors.Wrap(err, "ias: failed to create gRPC client")
	}

	auth := &registryAuthenticator{
		logger:   logging.GetLogger("cmd/ias/proxy/auth/registry"),
		conn:     conn,
		client:   registry.NewRegistryClient(conn),
		enclaves: newEnclaveStore(),
		initCh:   make(chan struct{}),
	}
	go auth.worker(ctx)

	return auth, nil
}
