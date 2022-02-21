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
)

var (
	// Sentry is the Sentry node basic scenario.
	Sentry scenario.Scenario = newSentryImpl("sentry", BasicKVTestClient)

	validatorExtraLogWatcherHandlerFactories = []log.WatcherHandlerFactory{
		oasis.LogAssertPeerExchangeDisabled(),
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
	// | Compute 0 +<---------->+ Sentry 3 |
	// +-----------+            +----------+
	//
	// +-----------+            +----------+
	// | Compute 1 +<---------->+ Sentry 4 |
	// +-----------+            +----------+
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
			ComputeWorkers: []int{0},
		},
		{
			ComputeWorkers: []int{1},
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

	f.ComputeWorkers = []oasis.ComputeWorkerFixture{
		{
			Entity:   1,
			Sentries: []int{3},
			// Disable cert rotation on one of the compute nodes so we can use
			// its TLS certificates in the access control sanity checks.
			DisableCertRotation: true,
			// Also disable public RPC on one, so we can check access control.
			DisablePublicRPC: true,
			Runtimes:         []int{1},
		},
		{
			Entity:   1,
			Sentries: []int{4},
			Runtimes: []int{1},
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

	compute0 := s.Net.ComputeWorkers()[0]
	compute0Identity, err := compute0.LoadIdentity()
	if err != nil {
		return fmt.Errorf("sentry: error loading compute node identity: %w", err)
	}
	// Make sure compute0 has disabled certificate rotation.
	if !compute0Identity.DoNotRotateTLS {
		return fmt.Errorf("sentry: compute-0 does not have disabled certificate rotation")
	}

	compute1 := s.Net.ComputeWorkers()[1]
	// Query for compute 1 TLS public keys.
	compute1Ctrl, err := oasis.NewController(compute1.SocketPath())
	if err != nil {
		return err
	}
	compute1Status, err := compute1Ctrl.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status for compute1: %w", err)
	}
	compute1ServerPublicKeys := make(map[signature.PublicKey]bool)
	for _, key := range compute1Status.Identity.TLS {
		compute1ServerPublicKeys[key] = true
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
