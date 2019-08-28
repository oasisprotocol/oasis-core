package ias

import (
	"context"
	"io"
	"sync"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	grpcRegistry "github.com/oasislabs/ekiden/go/grpc/registry"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

type registryAuthenticator struct {
	logger *logging.Logger

	conn   *grpc.ClientConn
	client grpcRegistry.RuntimeRegistryClient

	enclaves *enclaveStore

	initOnce sync.Once
	initCh   chan struct{}
}

func (auth *registryAuthenticator) VerifyEvidence(signer signature.PublicKey, evidence *ias.Evidence) error {
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
			"id", evidence.ID,
		)
		return err
	}

	auth.logger.Debug("allowing proxy request, found enclave identity",
		"id", evidence.ID,
	)
	return nil
}

func (auth *registryAuthenticator) worker(ctx context.Context) {
	defer auth.conn.Close()

	waitRuntimes := viper.GetInt(cfgWaitRuntimes)
	if waitRuntimes <= 0 {
		close(auth.initCh)
	}

	stream, err := auth.client.WatchRuntimes(ctx, &grpcRegistry.WatchRuntimesRequest{})
	if err != nil {
		auth.logger.Error("failed to start the WatchRuntimes stream",
			"err", err,
		)
		panic("unable to watch runtimes")
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pb, err := stream.Recv()
		if err == io.EOF {
			auth.logger.Error("data source stream closed by peer")
			panic("data source disappeared")
		}
		if err != nil {
			auth.logger.Error("runtime stream returned error",
				"err", err,
			)
			continue
		}

		var runtime registry.Runtime
		if err = runtime.FromProto(pb.GetRuntime()); err != nil {
			auth.logger.Error("malformed runtime protobuf",
				"err", err,
			)
			continue
		}

		n, err := auth.enclaves.addRuntime(&runtime)
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

func newRegistryAuthenticator(ctx context.Context, cmd *cobra.Command) (ias.GRPCAuthenticator, error) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		return nil, errors.Wrap(err, "ias: failed to create gRPC client")
	}

	auth := &registryAuthenticator{
		logger:   logging.GetLogger("cmd/ias/proxy/auth/registry"),
		conn:     conn,
		client:   grpcRegistry.NewRuntimeRegistryClient(conn),
		enclaves: newEnclaveStore(),
		initCh:   make(chan struct{}),
	}
	go auth.worker(ctx)

	return auth, nil
}
