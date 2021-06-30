package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/sentry/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

var (
	// Sentry is the Sentry node basic scenario.
	Sentry scenario.Scenario = newSentryImpl("sentry", BasicKVTestClient)
	// SentryEncryption is the Sentry node basic encryption scenario.
	SentryEncryption scenario.Scenario = newSentryImpl("sentry-encryption", BasicKVEncTestClient)

	validatorExtraLogWatcherHandlerFactories = []log.WatcherHandlerFactory{
		oasis.LogAssertPeerExchangeDisabled(),
	}

	emptyGetCheckpointsReq = &checkpoint.GetCheckpointsRequest{Namespace: runtimeID}

	emptySyncGetReq = &storage.GetRequest{
		Tree: syncer.TreeID{
			Root: storage.Root{
				Namespace: runtimeID,
			},
		},
	}
)

const sentryChecksContextTimeout = 30 * time.Second

type sentryImpl struct {
	runtimeImpl
}

func newSentryImpl(name string, testClient TestClient) scenario.Scenario {
	return &sentryImpl{
		runtimeImpl: *newRuntimeImpl(name, testClient),
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
			Consensus:                  oasis.ConsensusFixture{SupplementarySanityInterval: 1},
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
			// Also disable public RPC on one, so we can check access control.
			DisablePublicRPC: true,
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

func (s *sentryImpl) Run(childEnv *env.Env) error { // nolint: gocyclo
	// Run the basic runtime test.
	if err := s.runtimeImpl.Run(childEnv); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), sentryChecksContextTimeout)
	defer cancel()

	// Load identities and addresses used in the sanity checks.
	sentry0, _, sentry0CtrlAddress, sentry0P2PPubkey := loadSentryNodeInfo(s.Net.Sentries()[0])
	_, _, _, sentry1P2PPubkey := loadSentryNodeInfo(s.Net.Sentries()[1])
	_, _, _, sentry2P2PPubkey := loadSentryNodeInfo(s.Net.Sentries()[2])
	sentry3, sentry3Address, _, _ := loadSentryNodeInfo(s.Net.Sentries()[3])
	sentry4, sentry4Address, _, _ := loadSentryNodeInfo(s.Net.Sentries()[4])

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
	storage1Identity, err := storage0.LoadIdentity()
	if err != nil {
		return fmt.Errorf("sentry: error loading storage node identity: %w", err)
	}
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
	validator0Ctrl, err := oasis.NewController(validator0.SocketPath())
	if err != nil {
		return err
	}

	validator1 := s.Net.Validators()[1]
	validator1Identity, err := validator1.LoadIdentity()
	if err != nil {
		return fmt.Errorf("sentry: error loading validator node identity: %w", err)
	}
	validator1Ctrl, err := oasis.NewController(validator1.SocketPath())
	if err != nil {
		return err
	}

	validator2 := s.Net.Validators()[2]
	if err != nil {
		return fmt.Errorf("sentry: error loading validator node identity: %w", err)
	}
	validator2Ctrl, err := oasis.NewController(validator2.SocketPath())
	if err != nil {
		return err
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
	conn, err := s.dial(sentry0CtrlAddress, opts)
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
	conn, err = s.dial(sentry0CtrlAddress, opts)
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
	conn, err = s.dial(sentry0CtrlAddress, opts)
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
	if err != nil {
		return errors.New("storage1 checkpoint endpoint should allow connection with validator0 certificate")
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

	// Sanity check Sentry-3 storage endpoint. All nodes are allowed to access
	// storage sentry read only endpoints. Only active storage committee nodes
	// are allowed to access state access endpoints.

	// Check Sentry-3 storage endpoint with Validator-0 client certificates.
	opts = &cmnGrpc.ClientOptions{
		CommonName: identity.CommonName,
		ServerPubKeys: map[signature.PublicKey]bool{
			sentry3.GetTLSPubKey(): true,
		},
		Certificates: []tls.Certificate{*validator0Identity.TLSSentryClientCertificate},
	}
	conn, err = s.dial(sentry3Address, opts)
	if err != nil {
		return fmt.Errorf("sentry: dial error: %w", err)
	}
	defer conn.Close()
	sentry3Client := storage.NewStorageClient(conn)
	_, err = sentry3Client.SyncGet(ctx, emptySyncGetReq)
	s.Logger.Debug("sentry3.SyncGet with validator0 sentry cert", "err", err)
	if status.Code(err) != codes.PermissionDenied {
		return errors.New("sentry3 storage read-only endpoint should deny connections with validator0 certificate")
	}
	_, err = sentry3Client.GetCheckpoints(ctx, emptyGetCheckpointsReq)
	s.Logger.Debug("sentry3.GetCheckpoints with validator0 sentry cert", "err", err)
	if status.Code(err) == codes.PermissionDenied {
		return errors.New("sentry3 storage checkpoint endpoint should allow connection with validator0 sentry certificate")
	}

	// Check Sentry-3 storage endpoint with Storage-0 client certificates.
	opts = &cmnGrpc.ClientOptions{
		CommonName: identity.CommonName,
		ServerPubKeys: map[signature.PublicKey]bool{
			sentry4.GetTLSPubKey(): true,
		},
		Certificates: []tls.Certificate{*storage1Identity.GetTLSCertificate()},
	}
	conn, err = s.dial(sentry3Address, opts)
	if err != nil {
		return fmt.Errorf("sentry: dial error: %w", err)
	}
	defer conn.Close()
	sentry3Client = storage.NewStorageClient(conn)
	_, err = sentry3Client.SyncGet(ctx, emptySyncGetReq)
	s.Logger.Debug("sentry3.SyncGet with storage1 cert", "err", err)
	if status.Code(err) == codes.PermissionDenied {
		return errors.New("sentry3 storage read-only endpoint should allow connections with storage1 certificate")
	}
	_, err = sentry3Client.GetCheckpoints(ctx, emptyGetCheckpointsReq)
	s.Logger.Debug("sentry3.GetCheckpoints with storage1 cert", "err", err)
	if status.Code(err) == codes.PermissionDenied {
		return errors.New("sentry3 storage checkpoints endpoint should allow connection with storage1 certificate")
	}

	// Sanity check Sentry-4 storage endpoint. All nodes are allowed to access
	// storage sentry read only endpoints. Only active storage committee nodes
	// are allowed to access state access endpoints.

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
	_, err = sentry4Client.SyncGet(ctx, emptySyncGetReq)
	s.Logger.Debug("sentry4.SyncGet with validator0 sentry cert", "err", err)
	if status.Code(err) == codes.PermissionDenied {
		return errors.New("sentry4 storage read-only endpoint should allow connections with validator0 certificate")
	}
	_, err = sentry4Client.GetCheckpoints(ctx, emptyGetCheckpointsReq)
	s.Logger.Debug("sentry4.GetCheckpoints with validator0 sentry cert", "err", err)
	if status.Code(err) == codes.PermissionDenied {
		return errors.New("sentry4 storage checkpoint endpoint should allow connection with validator0 sentry certificate")
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
	_, err = sentry4Client.SyncGet(ctx, emptySyncGetReq)
	s.Logger.Debug("sentry4.SyncGet with storage0 cert", "err", err)
	if status.Code(err) == codes.PermissionDenied {
		return errors.New("sentry4 storage read-only endpoint should allow connections with storage0 certificate")
	}
	_, err = sentry4Client.GetCheckpoints(ctx, emptyGetCheckpointsReq)
	s.Logger.Debug("sentry4.GetCheckpoints with storage0 cert", "err", err)
	if err != nil {
		return errors.New("sentry4 storage checkpoints endpoint should allow connection with storage0 certificate")
	}

	// Sanity check validator peers - only sentry nodes should be present.
	// Expected consensus peers.
	validator0ExpectedPeerKeys := []string{
		strings.ToLower(crypto.PublicKeyToTendermint(&sentry0P2PPubkey).Address().String()),
		strings.ToLower(crypto.PublicKeyToTendermint(&sentry1P2PPubkey).Address().String()),
	}
	validator12ExpectedPeerKeys := []string{
		strings.ToLower(crypto.PublicKeyToTendermint(&sentry2P2PPubkey).Address().String()),
	}

	// Sanity check validator0.
	validator0Status, err := validator0Ctrl.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("validator0.GetStatus: %w", err)
	}
	validator0ConsensusPeers := consensusTendermintAddrs(validator0Status)
	if err = sanityCheckValidatorPeers(validator0ExpectedPeerKeys, validator0ConsensusPeers); err != nil {
		s.Logger.Error("validator0 invalid consensus peers",
			"expected", validator0ExpectedPeerKeys,
			"actual", validator0ConsensusPeers,
		)
		return err
	}

	// Sanity check validator1.
	validator1Status, err := validator1Ctrl.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("validator1.GetStatus: %w", err)
	}
	validator1ConsensusPeers := consensusTendermintAddrs(validator1Status)
	if err = sanityCheckValidatorPeers(validator12ExpectedPeerKeys, validator1ConsensusPeers); err != nil {
		s.Logger.Error("validator1 invalid consensus peers",
			"expected", validator12ExpectedPeerKeys,
			"actual", validator1ConsensusPeers,
		)
		return err
	}

	// Sanity check validator2.
	validator2Status, err := validator2Ctrl.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("validator2.GetStatus: %w", err)
	}
	validator2ConsensusPeers := consensusTendermintAddrs(validator2Status)
	if err = sanityCheckValidatorPeers(validator12ExpectedPeerKeys, validator2ConsensusPeers); err != nil {
		s.Logger.Error("validator2 invalid consensus peers",
			"expected", validator12ExpectedPeerKeys,
			"actual", validator2ConsensusPeers,
		)
		return err
	}
	return nil
}

func loadSentryNodeInfo(s *oasis.Sentry) (*oasis.Sentry, string, string, signature.PublicKey) {
	sentryCtrlAddress := s.GetSentryControlAddress()
	sentryAddress := s.GetSentryAddress()
	sentryIdentity, _ := s.LoadIdentity()
	sentryP2PPubkey := sentryIdentity.P2PSigner.Public()
	return s, sentryAddress, sentryCtrlAddress, sentryP2PPubkey
}

func consensusTendermintAddrs(status *control.Status) (consensusPeers []string) {
	for _, np := range status.Consensus.NodePeers {
		consensusPeers = append(consensusPeers, strings.Split(np, "@")[0])
	}
	return
}

func sanityCheckValidatorPeers(expected, actual []string) error {
	if len(expected) != len(actual) {
		return fmt.Errorf("consensus peers length mismatch, expected: %d, actual: %d",
			len(expected), len(actual))
	}
	for _, expect := range expected {
		var found bool
		for _, key := range actual {
			if key == expect {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("expected consensus peer missing: %s", expect)
		}
	}

	return nil
}
