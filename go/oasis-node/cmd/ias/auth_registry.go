package ias

import (
	"context"
	"sync"
	"time"

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

func (auth *registryAuthenticator) dialRegistry(ctx context.Context) (*grpc.ClientConn, error) {
	conn, err := cmdGrpc.NewClient(auth.cmd)
	if err != nil {
		return nil, errors.Wrap(err, "ias: failed to create gRPC client")
	}
	return conn, nil
}

func (auth *registryAuthenticator) worker(ctx context.Context) {
	waitRuntimes := viper.GetInt(cfgWaitRuntimes)
	if waitRuntimes <= 0 {
		close(auth.initCh)
	}

	var redialAttempts uint

Redial:
	redialAttempts++
	conn, err := auth.dialRegistry(ctx)
	if err != nil {
		auth.logger.Error("unable to connect to registry",
			"err", err,
		)
		if redialAttempts < 10 {
			time.Sleep(2 * time.Second)
			auth.logger.Info("attempting to re-dial registry")
			goto Redial
		}
		panic("unable to connect to registry")
	}
	defer conn.Close()
	client := registry.NewRegistryClient(conn)

	ch, sub, err := client.WatchRuntimes(ctx)
	if err != nil {
		auth.logger.Error("failed to start the WatchRuntimes stream",
			"err", err,
		)
		panic("unable to watch runtimes")
	}
	defer sub.Close()

	redialAttempts = 0

	for {
		var runtime *registry.Runtime
		select {
		case runtime = <-ch:
			if runtime == nil {
				auth.logger.Warn("data source stream closed by peer, re-dialing")
				goto Redial
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
	auth := &registryAuthenticator{
		logger:   logging.GetLogger("cmd/ias/proxy/auth/registry"),
		cmd:      cmd,
		enclaves: newEnclaveStore(),
		initCh:   make(chan struct{}),
	}
	go auth.worker(ctx)

	return auth, nil
}
