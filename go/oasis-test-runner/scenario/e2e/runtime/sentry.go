package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/sentry/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

var (
	// Sentry is the Sentry node basic scenario.
	Sentry scenario.Scenario = newSentryImpl("sentry", "simple-keyvalue-client", nil)
	// SentryEncryption is the Sentry node basic encryption scenario.
	SentryEncryption scenario.Scenario = newSentryImpl("sentry-encryption", "simple-keyvalue-enc-client", nil)

	validatorExtraLogWatcherHandlerFactories = []log.WatcherHandlerFactory{
		oasis.LogAssertPeerExchangeDisabled(),
	}

	emptyGetCheckpointsReq = &checkpoint.GetCheckpointsRequest{Namespace: runtimeID}
)

const sentryChecksContextTimeout = 30 * time.Second

type sentryImpl struct {
	runtimeImpl
}

func newSentryImpl(name, clientBinary string, clientArgs []string) scenario.Scenario {
	return &sentryImpl{
		runtimeImpl: *newRuntimeImpl(name, clientBinary, clientArgs),
	}
}

func (s *sentryImpl) Clone() scenario.Scenario {
	return &sentryImpl{
		runtimeImpl: *s.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (s *sentryImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := s.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Provision sentry nodes and validators with the following topology:
	//
	//                          +----------+
	//                     +--->| Sentry 0 |
	// +-------------+     |    +----------+
	// | Validator 0 +<----+    +----------+
	// |             +<-------->+ Sentry 1 |
	// +-------------+          +----------+
	//
	// +-------------+
	// | Validator 1 +<----+
	// +-------------+     |    +----------+
	// +-------------+     +--->+ Sentry 2 |
	// | Validator 2 +<-------->+          |
	// +-------------+          +----------+
	//
	// +-----------+            +----------+
	// | Storage 0 +<---------->+ Sentry 3 |
	// +-----------+            +----------+
	//
	// +-----------+            +----------+
	// | Storage 1 +<---------->+ Sentry 4 |
	// +-----------+            +----------+
	//
	// +------------+           +----------+
	// | Keymanager |<--------->| Sentry 5 |
	// +------------+           +----------+
	//
	f.Sentries = []oasis.SentryFixture{
		{
			Validators: []int{0},
		},
		{
			Validators: []int{0},
		},
		{
			Validators: []int{1, 2},
		},
		{
			StorageWorkers: []int{0},
		},
		{
			StorageWorkers: []int{1},
		},
		{
			KeymanagerWorkers: []int{0},
		},
	}

	f.Validators = []oasis.ValidatorFixture{
		{
			Entity:                     1,
			LogWatcherHandlerFactories: validatorExtraLogWatcherHandlerFactories,
			Sentries:                   []int{0, 1},
		},
		{
			Entity:                     1,
			LogWatcherHandlerFactories: validatorExtraLogWatcherHandlerFactories,
			Sentries:                   []int{2},
		},
		{
			Entity:                     1,
			LogWatcherHandlerFactories: validatorExtraLogWatcherHandlerFactories,
			Sentries:                   []int{2},
		},
	}

	f.StorageWorkers = []oasis.StorageWorkerFixture{
		{
			Backend:  database.BackendNameBadgerDB,
			Entity:   1,
			Sentries: []int{3},
			// Disable cert rotation on one of the storage nodes so we can use
			// its TLS certificates in the access control sanity checks.
			DisableCertRotation: true,
		},
		{
			Backend:  database.BackendNameBadgerDB,
			Entity:   1,
			Sentries: []int{4},
		},
	}

	f.Keymanagers = []oasis.KeymanagerFixture{
		{
			Runtime:  0,
			Entity:   1,
			Sentries: []int{5},
		},
	}

	return f, nil
}

func (s *sentryImpl) dial(address string, clientOpts *cmnGrpc.ClientOptions) (*grpc.ClientConn, error) {
	creds, err := cmnGrpc.NewClientCreds(clientOpts)
	if err != nil {
		return nil, err
	}
	opts := grpc.WithTransportCredentials(creds)
	conn, err := cmnGrpc.Dial(address, opts) // nolint: staticcheck
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (s *sentryImpl) Run(childEnv *env.Env) error {
	// Run the basic runtime test.
	if err := s.runtimeImpl.Run(childEnv); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), sentryChecksContextTimeout)
	defer cancel()

	// Load identities and addresses used in the sanity checks.
	sentry0 := s.Net.Sentries()[0]
	sentry0Address := sentry0.GetSentryControlAddress()

	sentry4 := s.Net.Sentries()[4]
	sentry4Address := sentry4.GetSentryAddress()

	storage0 := s.Net.StorageWorkers()[0]
	storage0Identity, err := storage0.LoadIdentity()
	if err != nil {
		return fmt.Errorf("sentry: error loading storage node identity: %w", err)
	}
	// Make sure storage0 has disabled certificate rotation.
	if !storage0Identity.DoNotRotateTLS {
		return fmt.Errorf("sentry: storage-0 does not have disabled certificate rotation")
	}

	storage1 := s.Net.StorageWorkers()[1]
	storage1Address := storage1.GetClientAddress()
	// Query for storage 1 TLS public keys.
	storage1Ctrl, err := oasis.NewController(storage1.SocketPath())
	if err != nil {
		return err
	}
	storage1Status, err := storage1Ctrl.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status for storage1: %w", err)
	}
	storage1ServerPublicKeys := make(map[signature.PublicKey]bool)
	for _, key := range storage1Status.Identity.TLS {
		storage1ServerPublicKeys[key] = true
	}

	validator0 := s.Net.Validators()[0]
	validator0Identity, err := validator0.LoadIdentity()
	if err != nil {
		return fmt.Errorf("sentry: error loading validator node identity: %w", err)
	}

	validator1 := s.Net.Validators()[1]
	validator1Identity, err := validator1.LoadIdentity()
	if err != nil {
		return fmt.Errorf("sentry: error loading validator node identity: %w", err)
	}

	// Sanity check sentry control endpoints. Only configured upstream nodes are
	// allowed to access their corresponding sentry control endpoint.

	// Check Sentry-0 control endpoint without client certificates.
	opts := &cmnGrpc.ClientOptions{
		CommonName: identity.CommonName,
		ServerPubKeys: map[signature.PublicKey]bool{
			sentry0.GetTLSPubKey(): true,
		},
		Certificates: []tls.Certificate{},
	}
	conn, err := s.dial(sentry0Address, opts)
	if err != nil {
		return fmt.Errorf("sentry: dial error: %w", err)
	}
	defer conn.Close()
	sentry0Client := api.NewSentryClient(conn)
	_, err = sentry0Client.GetAddresses(ctx)
	s.Logger.Debug("sentry0.GetAddress without cert", "err", err)
	if status.Code(err) != codes.PermissionDenied {
		return errors.New("sentry0 control endpoint should deny connection without certificate")
	}

	// Check Sentry-0 control endpoint with Validator-1 client certificates.
	opts = &cmnGrpc.ClientOptions{
		CommonName: identity.CommonName,
		ServerPubKeys: map[signature.PublicKey]bool{
			sentry0.GetTLSPubKey(): true,
		},
		Certificates: []tls.Certificate{*validator1Identity.TLSSentryClientCertificate},
	}
	conn, err = s.dial(sentry0Address, opts)
	if err != nil {
		return fmt.Errorf("sentry: dial error: %w", err)
	}
	defer conn.Close()
	sentry0Client = api.NewSentryClient(conn)
	_, err = sentry0Client.GetAddresses(ctx)
	s.Logger.Debug("sentry0.GetAddress with validator1 sentry cert", "err", err)
	if status.Code(err) != codes.PermissionDenied {
		return errors.New("sentry0 control endpoint should deny connection with validator1 certificate")
	}

	// Check Sentry-0 control endpoint with Validator-0 client certificates.
	opts = &cmnGrpc.ClientOptions{
		CommonName: identity.CommonName,
		ServerPubKeys: map[signature.PublicKey]bool{
			sentry0.GetTLSPubKey(): true,
		},
		Certificates: []tls.Certificate{*validator0Identity.TLSSentryClientCertificate},
	}
	conn, err = s.dial(sentry0Address, opts)
	if err != nil {
		return fmt.Errorf("sentry: dial error: %w", err)
	}
	defer conn.Close()
	sentry0Client = api.NewSentryClient(conn)
	_, err = sentry0Client.GetAddresses(ctx)
	s.Logger.Debug("sentry0.GetAddress with validator0 sentry cert", "err", err)
	if err != nil {
		return errors.New("sentry0 control endpoint should allow connection with validator0 certificate")
	}

	// Sanity check storage endpoints. Only committee and configured upstream sentry nodes
	// are allowed to access corresponding storage node write endpoints.

	// Check Storage-1 endpoint with Validator-0 client certificates.
	opts = &cmnGrpc.ClientOptions{
		CommonName:    identity.CommonName,
		ServerPubKeys: storage1ServerPublicKeys,
		Certificates:  []tls.Certificate{*validator0Identity.TLSSentryClientCertificate},
	}
	conn, err = s.dial(storage1Address, opts)
	if err != nil {
		return fmt.Errorf("sentry: dial error: %w", err)
	}
	defer conn.Close()
	storage1Client := storage.NewStorageClient(conn)
	_, err = storage1Client.GetCheckpoints(ctx, emptyGetCheckpointsReq)
	s.Logger.Debug("storage1.GetCheckpoints with validator0 cert", "err", err)
	if status.Code(err) != codes.PermissionDenied {
		return errors.New("storage1 checkpoint endpoint should deny connection with validator0 certificate")
	}

	// Check Storage-1 endpoint with Storage-0 client certificates.
	opts = &cmnGrpc.ClientOptions{
		CommonName:    identity.CommonName,
		ServerPubKeys: storage1ServerPublicKeys,
		Certificates:  []tls.Certificate{*storage0Identity.GetTLSCertificate()},
	}
	conn, err = s.dial(storage1Address, opts)
	if err != nil {
		return fmt.Errorf("sentry: dial error: %w", err)
	}
	defer conn.Close()
	storage1Client = storage.NewStorageClient(conn)
	_, err = storage1Client.GetCheckpoints(ctx, emptyGetCheckpointsReq)
	s.Logger.Debug("storage1.GetCheckpoints with storage0 cert", "err", err)
	if err != nil {
		return errors.New("storage1 checkpoints endpoint should allow connection with storage0 certificate")
	}

	// Sanity check Sentry-4 storage endpoint. All nodes are allowed to access
	// storage sentry read only endpoints. Only active storage committee nodes
	// are allowed to access checkpoint endpoints.

	// Check Sentry-4 storage endpoint with Validator-0 client certificates.
	opts = &cmnGrpc.ClientOptions{
		CommonName: identity.CommonName,
		ServerPubKeys: map[signature.PublicKey]bool{
			sentry4.GetTLSPubKey(): true,
		},
		Certificates: []tls.Certificate{*validator0Identity.TLSSentryClientCertificate},
	}
	conn, err = s.dial(sentry4Address, opts)
	if err != nil {
		return fmt.Errorf("sentry: dial error: %w", err)
	}
	defer conn.Close()
	sentry4Client := storage.NewStorageClient(conn)
	_, err = sentry4Client.SyncGet(ctx, &storage.GetRequest{})
	s.Logger.Debug("sentry4.SyncGet with validator0 sentry cert", "err", err)
	// XXX: since we make an invalid request the request does fail, but ensure
	// it makes past access control.
	if status.Code(err) == codes.PermissionDenied {
		return errors.New("sentry4 storage read-only endpoint should allow connections with validator0 certificate")
	}
	_, err = sentry4Client.GetCheckpoints(ctx, emptyGetCheckpointsReq)
	s.Logger.Debug("sentry4.GetCheckpoints with validator0 sentry cert", "err", err)
	if status.Code(err) != codes.PermissionDenied {
		return errors.New("sentry4 storage checkpoint endpoint should deny connection with validator0 sentry certificate")
	}

	// Check Sentry-4 storage endpoint with Storage-0 client certificates.
	opts = &cmnGrpc.ClientOptions{
		CommonName: identity.CommonName,
		ServerPubKeys: map[signature.PublicKey]bool{
			sentry4.GetTLSPubKey(): true,
		},
		Certificates: []tls.Certificate{*storage0Identity.GetTLSCertificate()},
	}
	conn, err = s.dial(sentry4Address, opts)
	if err != nil {
		return fmt.Errorf("sentry: dial error: %w", err)
	}
	defer conn.Close()
	sentry4Client = storage.NewStorageClient(conn)
	_, err = sentry4Client.SyncGet(ctx, &storage.GetRequest{})
	s.Logger.Debug("sentry4.SyncGet with storage0 cert", "err", err)
	// XXX: since we make an invalid request the request does fail, but ensure
	// it makes past access control.
	if status.Code(err) == codes.PermissionDenied {
		return errors.New("sentry4 storage read-only endpoint should allow connections with validator0 certificate")
	}
	_, err = sentry4Client.GetCheckpoints(ctx, emptyGetCheckpointsReq)
	s.Logger.Debug("sentry4.GetCheckpoints with storage0 cert", "err", err)
	if err != nil {
		return errors.New("sentry4 storage checkpoints endpoint should allow connection with storage0 certificate")
	}

	return nil
}
