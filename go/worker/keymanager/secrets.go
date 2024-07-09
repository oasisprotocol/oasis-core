package keymanager

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/libp2p/go-libp2p/core"
	"golang.org/x/exp/maps"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	p2pAPI "github.com/oasisprotocol/oasis-core/go/p2p/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	workerKm "github.com/oasisprotocol/oasis-core/go/worker/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

const (
	generateSecretMaxRetries = 5
	loadSecretMaxRetries     = 5
	ephemeralSecretCacheSize = 20
)

var insecureRPCMethods = map[string]struct{}{
	secrets.RPCMethodGetPublicKey:          {},
	secrets.RPCMethodGetPublicEphemeralKey: {},
}

var secureRPCMethods = map[string]struct{}{
	secrets.RPCMethodGetOrCreateKeys:          {},
	secrets.RPCMethodGetOrCreateEphemeralKeys: {},
	secrets.RPCMethodReplicateMasterSecret:    {},
	secrets.RPCMethodReplicateEphemeralSecret: {},
}

// Ensure the secrets worker implements the RPCAccessController interface.
var _ workerKm.RPCAccessController = (*secretsWorker)(nil)

type secretsWorker struct {
	mu sync.RWMutex

	logger *logging.Logger

	initCh chan struct{}

	runtimeID    common.Namespace
	runtimeLabel string

	privatePeers map[core.PeerID]struct{}

	kmWorker     *Worker
	commonWorker *workerCommon.Worker
	roleProvider registration.RoleProvider
	backend      api.Backend

	status   workerKm.SecretsStatus // Guarded by mutex.
	kmStatus *secrets.Status

	initEnclaveInProgress  bool
	initEnclaveRequired    bool
	initEnclaveDoneCh      chan *secrets.SignedInitResponse
	initEnclaveRetryCh     <-chan time.Time
	initEnclaveRetryTicker *backoff.Ticker

	mstSecret *secrets.SignedEncryptedMasterSecret

	loadMstSecRetry     int
	genMstSecDoneCh     chan bool
	genMstSecEpoch      beacon.EpochTime
	genMstSecInProgress bool
	genMstSecRetry      int

	ephSecret *secrets.SignedEncryptedEphemeralSecret

	loadEphSecRetry     int
	genEphSecDoneCh     chan bool
	genEphSecInProgress bool
	genEphSecRetry      int

	genSecHeight int64
}

// newSecretsWorker constructs a new key manager master and ephemeral secret worker.
func newSecretsWorker(
	runtimeID common.Namespace,
	commonWorker *workerCommon.Worker,
	kmWorker *Worker,
	r *registration.Worker,
	backend api.Backend,
) (*secretsWorker, error) {
	roleProvider, err := r.NewRuntimeRoleProvider(node.RoleKeyManager, runtimeID)
	if err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to create role provider: %w", err)
	}

	privatePeers := make(map[core.PeerID]struct{})
	for _, b64pk := range config.GlobalConfig.Keymanager.PrivatePeerPubKeys {
		pkBytes, err := base64.StdEncoding.DecodeString(b64pk)
		if err != nil {
			return nil, fmt.Errorf("oasis/keymanager: `%s` is not a base64-encoded public key (%w)", b64pk, err)
		}
		var pk signature.PublicKey
		if err = pk.UnmarshalBinary(pkBytes); err != nil {
			return nil, fmt.Errorf("oasis/keymanager: `%s` is not a public key (%w)", b64pk, err)
		}
		peerID, err := p2pAPI.PublicKeyToPeerID(pk)
		if err != nil {
			return nil, fmt.Errorf("oasis/keymanager: `%s` can not be converted to a peer id (%w)", b64pk, err)
		}
		privatePeers[peerID] = struct{}{}
	}

	var status workerKm.SecretsStatus
	for p := range privatePeers {
		status.Worker.PrivatePeers = append(status.Worker.PrivatePeers, p)
	}
	status.Worker.Status = workerKm.StatusStateStopped

	return &secretsWorker{
		logger:            logging.GetLogger("worker/keymanager/secrets"),
		initCh:            make(chan struct{}),
		runtimeID:         runtimeID,
		runtimeLabel:      runtimeID.String(),
		roleProvider:      roleProvider,
		privatePeers:      privatePeers,
		kmWorker:          kmWorker,
		commonWorker:      commonWorker,
		backend:           backend,
		initEnclaveDoneCh: make(chan *secrets.SignedInitResponse, 1),
		genMstSecDoneCh:   make(chan bool, 1),
		genMstSecEpoch:    math.MaxUint64,
		genEphSecDoneCh:   make(chan bool, 1),
		genSecHeight:      int64(math.MaxInt64),
		status:            status,
	}, nil
}

// Methods implements RPCAccessController interface.
func (w *secretsWorker) Methods() []string {
	var methods []string
	methods = append(methods, maps.Keys(secureRPCMethods)...)
	methods = append(methods, maps.Keys(insecureRPCMethods)...)
	return methods
}

// Connect implements RPCAccessController interface.
func (w *secretsWorker) Connect(ctx context.Context, peerID core.PeerID) bool {
	// Start accepting requests after initialization.
	w.mu.RLock()
	state := w.status.Worker.Status
	kmStatus := w.status.Status
	w.mu.RUnlock()

	if state != workerKm.StatusStateReady || kmStatus == nil {
		return false
	}

	// Secure methods are accessible to private peers without restrictions.
	if _, ok := w.privatePeers[peerID]; ok {
		return true
	}

	// Other peers must undergo the authorization process.
	if err := w.authorizeNode(ctx, peerID, kmStatus); err == nil {
		return true
	}
	if err := w.authorizeKeyManager(peerID); err == nil {
		return true
	}

	return false
}

// Authorize implements RPCAccessController interface.
func (w *secretsWorker) Authorize(ctx context.Context, method string, kind enclaverpc.Kind, peerID core.PeerID) error {
	// Start accepting requests after initialization.
	w.mu.RLock()
	state := w.status.Worker.Status
	kmStatus := w.status.Status
	w.mu.RUnlock()

	if state != workerKm.StatusStateReady || kmStatus == nil {
		return fmt.Errorf("not initialized")
	}

	// Check if the method is supported.
	switch kind {
	case enclaverpc.KindInsecureQuery:
		if _, ok := insecureRPCMethods[method]; !ok {
			return fmt.Errorf("unsupported method: %s", method)
		}
		return nil
	case enclaverpc.KindNoiseSession:
		if _, ok := secureRPCMethods[method]; !ok {
			return fmt.Errorf("unsupported method: %s", method)
		}
	default:
		return fmt.Errorf("unsupported kind: %s", kind)
	}

	// Secure methods are accessible to private peers without restrictions.
	if _, ok := w.privatePeers[peerID]; ok {
		return nil
	}

	// Other peers must undergo the authorization process.
	switch method {
	case secrets.RPCMethodGetOrCreateKeys, secrets.RPCMethodGetOrCreateEphemeralKeys:
		return w.authorizeNode(ctx, peerID, kmStatus)
	case secrets.RPCMethodReplicateMasterSecret, secrets.RPCMethodReplicateEphemeralSecret:
		return w.authorizeKeyManager(peerID)
	default:
		return fmt.Errorf("unsupported method: %s", method)
	}
}

func (w *secretsWorker) authorizeNode(ctx context.Context, peerID core.PeerID, kmStatus *secrets.Status) error {
	rt, err := w.kmWorker.runtime.RegistryDescriptor(ctx)
	if err != nil {
		return err
	}

	switch rt.TEEHardware {
	case node.TEEHardwareInvalid:
		// Insecure key manager enclaves can be queried by all runtimes (used for testing).
		if kmStatus.IsSecure {
			return fmt.Errorf("untrusted hardware")
		}
		return nil
	case node.TEEHardwareIntelSGX:
		// Secure key manager enclaves can be queried by runtimes specified in the policy.
		if kmStatus.Policy == nil {
			return fmt.Errorf("policy not set")
		}
		rts := w.kmWorker.accessList.Runtimes(peerID)
		for _, enc := range kmStatus.Policy.Policy.Enclaves { // TODO: Use the right enclave identity.
			for rtID := range enc.MayQuery {
				if rts.Contains(rtID) {
					return nil
				}
			}
		}
		return fmt.Errorf("query not allowed")
	default:
		return fmt.Errorf("unsupported hardware: %s", rt.TEEHardware)
	}
}

func (w *secretsWorker) authorizeKeyManager(peerID core.PeerID) error {
	// Allow only peers within the same key manager runtime.
	if !w.kmWorker.accessList.Runtimes(peerID).Contains(w.runtimeID) {
		return fmt.Errorf("not a key manager")
	}
	return nil
}

// Initialized returns a channel that will be closed when the worker is initialized
// and registered with the consensus layer using the latest `init` response.
func (w *secretsWorker) Initialized() <-chan struct{} {
	return w.initCh
}

// GetStatus returns the key manager master and ephemeral secrets worker status.
func (w *secretsWorker) GetStatus() *workerKm.SecretsStatus {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return &workerKm.SecretsStatus{
		Worker: w.status.Worker,
		Status: w.status.Status,
	}
}

func (w *secretsWorker) work(ctx context.Context, hrt host.RichRuntime) {
	w.logger.Info("starting master and ephemeral secrets worker")

	// Signal that the worker started.
	w.mu.Lock()
	w.status.Worker.Status = workerKm.StatusStateStarting
	w.mu.Unlock()

	// Subscribe to runtime events to re-initialize on restarts.
	// Note that some events may be missed if the runtime is already running.
	hrtEventCh, hrtSub := hrt.WatchEvents()
	defer hrtSub.Close()

	// Subscribe to key manager status updates.
	statusCh, statusSub := w.backend.Secrets().WatchStatuses()
	defer statusSub.Close()

	// Subscribe to key manager master secret publications.
	mstCh, mstSub := w.backend.Secrets().WatchMasterSecrets()
	defer mstSub.Close()

	// Subscribe to key manager ephemeral secret publications.
	ephCh, ephSub := w.backend.Secrets().WatchEphemeralSecrets()
	defer ephSub.Close()

	// Subscribe to epoch transitions in order to know when we need to choose
	// a random block height for secret generation.
	epoch, err := w.commonWorker.Consensus.Beacon().GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		w.logger.Error("failed to fetch current epoch",
			"err", err,
		)
		return
	}
	epoCh, epoSub, err := w.commonWorker.Consensus.Beacon().WatchLatestEpoch(ctx)
	if err != nil {
		w.logger.Error("failed to watch epochs",
			"err", err,
		)
		return
	}
	defer epoSub.Close()

	// Watch block heights so we can impose a random ephemeral secret
	// generation delay.
	blkCh, blkSub, err := w.commonWorker.Consensus.WatchBlocks(ctx)
	if err != nil {
		w.logger.Error("failed to watch blocks",
			"err", err,
		)
		return
	}
	defer blkSub.Close()

	// Don't block node registration.
	w.roleProvider.SetAvailable(func(_ *node.Node) error { return nil })

	for run := true; run; {
		select {
		case epoch = <-epoCh:
			w.handleNewEpoch(epoch)
		case blk := <-blkCh:
			w.handleNewBlock(ctx, blk, epoch)
		case ev := <-hrtEventCh:
			w.handleRuntimeHostEvent(ctx, ev)
		case kmStatus := <-statusCh:
			w.handleStatusUpdate(ctx, kmStatus)
		case <-w.initEnclaveRetryCh:
			w.handleInitEnclave(ctx)
		case rsp := <-w.initEnclaveDoneCh:
			w.handleInitEnclaveDone(ctx, rsp)
		case secret := <-mstCh:
			w.handleNewMasterSecret(ctx, secret)
		case ok := <-w.genMstSecDoneCh:
			w.handleGenerateMasterSecretDone(ok)
		case secret := <-ephCh:
			w.handleNewEphemeralSecret(ctx, secret, epoch)
		case ok := <-w.genEphSecDoneCh:
			w.handleGenerateEphemeralSecretDone(ok)
		case <-ctx.Done():
			run = false
		}
	}

	w.logger.Info("stopping master and ephemeral secrets worker")

	// Wait until tasks running in the background finish.
	if w.initEnclaveInProgress {
		<-w.initEnclaveDoneCh
	}
	if w.genMstSecInProgress {
		<-w.genMstSecDoneCh
	}
	if w.genEphSecInProgress {
		<-w.genEphSecDoneCh
	}

	// Signal that the worker stopped.
	w.mu.Lock()
	w.status.Worker.Status = workerKm.StatusStateStopped
	w.mu.Unlock()
}

func (w *secretsWorker) handleNewEpoch(epoch beacon.EpochTime) {
	// Choose a random height for generating master/ephemeral secrets to prevent key managers from
	// all publishing transactions simultaneously, which would result in unnecessary gas waste.
	// Additionally, avoid selecting blocks at the end of the epoch, as secret generation,
	// publication and replication takes some time.
	height, err := w.kmWorker.selectBlockHeight(epoch, 10, 50)
	if err != nil {
		// If randomization fails, the height will be set to zero meaning that
		// the secrets will be generated immediately without a delay.
		w.logger.Error("failed to select a random block height",
			"err", err,
		)
	}

	w.logger.Debug("block height for generating secrets selected",
		"height", height,
		"epoch", epoch,
	)

	// Reset retries.
	w.genSecHeight = height
	w.genMstSecRetry = 0
	w.genEphSecRetry = 0
}

func (w *secretsWorker) handleNewBlock(ctx context.Context, blk *consensus.Block, epoch beacon.EpochTime) {
	if blk == nil {
		w.logger.Error("watch blocks channel closed unexpectedly")
		return
	}

	// (Re)Generate master/ephemeral secrets once we reach the chosen height and epoch.
	w.handleGenerateMasterSecret(ctx, blk.Height, epoch)
	w.handleGenerateEphemeralSecret(ctx, blk.Height, epoch)

	// (Re)Load master/ephemeral secrets.
	w.handleLoadMasterSecret(ctx)
	w.handleLoadEphemeralSecret(ctx)
}

func (w *secretsWorker) handleRuntimeHostEvent(ctx context.Context, ev *host.Event) {
	switch {
	case ev.Started != nil:
		// The runtime attestation key changes on startup, invalidating the signature of the
		// last init response. Therefore, we need to re-initialize again.
		//
		// Missing the first event is not an issue, as we always initialize the enclave
		// when the first status update is received.
		w.handleInitEnclave(ctx)
	}
}

func (w *secretsWorker) handleStatusUpdate(ctx context.Context, kmStatus *secrets.Status) {
	if kmStatus == nil || !kmStatus.ID.Equal(&w.runtimeID) {
		return
	}

	w.logger.Debug("key manager status updated",
		"generation", kmStatus.Generation,
		"rotation_epoch", kmStatus.RotationEpoch,
		"checksum", hex.EncodeToString(kmStatus.Checksum),
		"nodes", kmStatus.Nodes,
	)

	// Update metrics.
	consensusMasterSecretGenerationNumber.WithLabelValues(w.runtimeLabel).Set(float64(kmStatus.Generation))
	consensusMasterSecretRotationEpochNumber.WithLabelValues(w.runtimeLabel).Set(float64(kmStatus.RotationEpoch))

	// Cache the latest status.
	w.kmStatus = kmStatus
	w.mu.Lock()
	w.status.Status = kmStatus
	w.mu.Unlock()

	// (Re)Initialize the enclave.
	// A new master secret generation or policy might have been published.
	w.handleInitEnclave(ctx)

	// The epoch for generating the next master secret may change with the policy update.
	w.updateGenerateMasterSecretEpoch()
}

func (w *secretsWorker) handleInitEnclave(ctx context.Context) {
	if w.kmStatus == nil {
		// There's no need to retry as another call will be made
		// once the key manager status is set/updated.
		return
	}
	if w.initEnclaveInProgress {
		// Try again later, immediately after the current task finishes.
		w.initEnclaveRequired = true
		return
	}

	// Lock. Allow only one active initialization.
	w.initEnclaveRequired = false
	w.initEnclaveInProgress = true

	// Enclave initialization can take a long time (e.g. when master secrets
	// need to be replicated), so don't block the loop.
	initEnclave := func(kmStatus *secrets.Status) {
		rsp, err := w.initEnclave(ctx, kmStatus)
		if err != nil {
			w.logger.Error("failed to initialize enclave",
				"err", err,
			)
		}
		w.initEnclaveDoneCh <- rsp
	}

	go initEnclave(w.kmStatus)
}

func (w *secretsWorker) initEnclave(ctx context.Context, kmStatus *secrets.Status) (*secrets.SignedInitResponse, error) {
	w.logger.Info("initializing key manager enclave")

	// Initialize the key manager.
	args := secrets.InitRequest{
		Status: *kmStatus,
	}
	var rsp secrets.SignedInitResponse
	if err := w.kmWorker.callEnclaveLocal(ctx, secrets.RPCMethodInit, args, &rsp); err != nil {
		w.logger.Error("failed to initialize enclave",
			"err", err,
		)
		return nil, fmt.Errorf("worker/keymanager: failed to initialize enclave: %w", err)
	}

	// Validate the signature.
	rak, err := w.kmWorker.runtimeAttestationKey()
	if err != nil {
		return nil, err
	}
	if err := rsp.Verify(*rak); err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to validate initialization response signature: %w", err)
	}

	if !rsp.InitResponse.IsSecure {
		w.logger.Warn("key manager enclave build is INSECURE")
	}

	w.logger.Info("key manager enclave initialized",
		"is_secure", rsp.InitResponse.IsSecure,
		"checksum", hex.EncodeToString(rsp.InitResponse.Checksum),
		"next_checksum", hex.EncodeToString(rsp.InitResponse.NextChecksum),
		"policy_checksum", hex.EncodeToString(rsp.InitResponse.PolicyChecksum),
		"rsk", rsp.InitResponse.RSK,
		"next_rsk", rsp.InitResponse.NextRSK,
	)

	w.mu.Lock()
	defer w.mu.Unlock()

	// Update metrics.
	enclaveMasterSecretGenerationNumber.WithLabelValues(w.runtimeLabel).Set(float64(kmStatus.Generation))
	if !bytes.Equal(w.status.Worker.PolicyChecksum, rsp.InitResponse.PolicyChecksum) {
		policyUpdateCount.WithLabelValues(w.runtimeLabel).Inc()
	}

	// Update status.
	w.status.Worker.Policy = kmStatus.Policy
	w.status.Worker.PolicyChecksum = rsp.InitResponse.PolicyChecksum

	return &rsp, nil
}

func (w *secretsWorker) handleInitEnclaveDone(ctx context.Context, rsp *secrets.SignedInitResponse) {
	// Discard the response if the runtime is not ready and retry later.
	version, err := w.kmWorker.GetHostedRuntimeActiveVersion()
	if err != nil {
		rsp = nil
	}

	// Unlock.
	w.initEnclaveInProgress = false

	// Stop or set up the retry ticker, depending on whether the initialization failed.
	switch {
	case rsp != nil && w.initEnclaveRetryTicker != nil:
		w.initEnclaveRetryTicker.Stop()
		w.initEnclaveRetryTicker = nil
		w.initEnclaveRetryCh = nil
	case rsp == nil && w.initEnclaveRetryTicker == nil && !w.initEnclaveRequired:
		w.initEnclaveRetryTicker = backoff.NewTicker(cmnBackoff.NewExponentialBackOff())
		w.initEnclaveRetryCh = w.initEnclaveRetryTicker.C
	}

	// Ensure the enclave is up-to-date with the latest key manager status.
	// For example, if the replication of master secrets took a long time,
	// new secrets might have been generated and they need to be replicated too.
	if w.initEnclaveRequired {
		w.handleInitEnclave(ctx)
		return
	}

	// (Re)Register the node with the latest init response.
	if rsp != nil {
		w.registerNode(rsp, *version)
	}
}

func (w *secretsWorker) registerNode(rsp *secrets.SignedInitResponse, version version.Version) {
	w.logger.Info("registering key manager",
		"is_secure", rsp.InitResponse.IsSecure,
		"checksum", hex.EncodeToString(rsp.InitResponse.Checksum),
		"policy_checksum", hex.EncodeToString(rsp.InitResponse.PolicyChecksum),
		"rsk", rsp.InitResponse.RSK,
		"next_rsk", rsp.InitResponse.NextRSK,
	)

	// Register as we are now ready to handle requests.
	extraInfo := cbor.Marshal(rsp)

	w.roleProvider.SetAvailableWithCallback(func(n *node.Node) error {
		rt := n.AddOrUpdateRuntime(w.runtimeID, version)
		rt.ExtraInfo = extraInfo
		return nil
	}, func(context.Context) error {
		w.logger.Info("key manager registered (extra info updated)")

		// Signal that we are initialized.
		w.mu.Lock()
		w.status.Worker.LastRegistration = time.Now()
		w.status.Worker.Status = workerKm.StatusStateReady
		w.mu.Unlock()

		select {
		case <-w.initCh:
		default:
			w.logger.Info("key manager initialized")
			close(w.initCh)
		}

		return nil
	})
}

func (w *secretsWorker) updateGenerateMasterSecretEpoch() {
	var nextEpoch beacon.EpochTime

	// If at least one master secret has been generated, respect the rotation interval.
	nextGen := w.kmStatus.NextGeneration()
	if nextGen != 0 {
		var rotationInterval beacon.EpochTime
		if w.kmStatus.Policy != nil {
			rotationInterval = w.kmStatus.Policy.Policy.MasterSecretRotationInterval
		}

		switch rotationInterval {
		case 0:
			// Rotation not allowed.
			nextEpoch = math.MaxUint64
		default:
			// Secrets are allowed to be generated at most one epoch before the rotation.
			nextEpoch = w.kmStatus.RotationEpoch + rotationInterval - 1
		}
	}

	// If a master secret has been proposed, wait for the next epoch.
	if w.mstSecret != nil && nextEpoch < w.mstSecret.Secret.Epoch {
		nextEpoch = w.mstSecret.Secret.Epoch
	}

	w.genMstSecEpoch = nextEpoch

	w.logger.Debug("epoch for generating master secret updated",
		"epoch", w.genMstSecEpoch,
	)
}

func (w *secretsWorker) handleNewMasterSecret(ctx context.Context, secret *secrets.SignedEncryptedMasterSecret) {
	if !secret.Secret.ID.Equal(&w.runtimeID) {
		return
	}

	w.logger.Debug("new master secret proposed",
		"generation", secret.Secret.Generation,
		"epoch", secret.Secret.Epoch,
		"checksum", hex.EncodeToString(secret.Secret.Secret.Checksum),
	)

	// Update metrics.
	consensusMasterSecretProposalGenerationNumber.WithLabelValues(w.runtimeLabel).Set(float64(secret.Secret.Generation))
	consensusMasterSecretProposalEpochNumber.WithLabelValues(w.runtimeLabel).Set(float64(secret.Secret.Epoch))

	// Rearm master secret loading.
	w.mstSecret = secret
	w.loadMstSecRetry = 0

	w.updateGenerateMasterSecretEpoch()
	w.handleLoadMasterSecret(ctx)
}

func (w *secretsWorker) handleLoadMasterSecret(ctx context.Context) {
	if w.kmStatus == nil || w.mstSecret == nil {
		return
	}
	if w.loadMstSecRetry > loadSecretMaxRetries {
		return
	}

	// Retry only few times per epoch.
	w.loadMstSecRetry++

	if err := w.loadMasterSecret(ctx, w.mstSecret); err != nil {
		w.logger.Error("failed to load master secret",
			"err", err,
			"retry", w.loadMstSecRetry-1,
		)
		return
	}

	// Disarm master secret loading.
	w.loadMstSecRetry = math.MaxInt64

	// Announce that the enclave has replicated the proposal for the next master
	// secret and is ready for rotation.
	w.handleInitEnclave(ctx)
}

func (w *secretsWorker) loadMasterSecret(ctx context.Context, sigSecret *secrets.SignedEncryptedMasterSecret) error {
	w.logger.Info("loading master secret",
		"generation", sigSecret.Secret.Generation,
		"epoch", sigSecret.Secret.Epoch,
	)

	args := secrets.LoadMasterSecretRequest{
		SignedSecret: *sigSecret,
	}

	var rsp protocol.Empty
	if err := w.kmWorker.callEnclaveLocal(ctx, secrets.RPCMethodLoadMasterSecret, args, &rsp); err != nil {
		w.logger.Error("failed to load master secret",
			"err", err,
		)
		return fmt.Errorf("failed to load master secret: %w", err)
	}

	// Update metrics.
	enclaveMasterSecretProposalGenerationNumber.WithLabelValues(w.runtimeLabel).Set(float64(w.mstSecret.Secret.Generation))
	enclaveMasterSecretProposalEpochNumber.WithLabelValues(w.runtimeLabel).Set(float64(w.mstSecret.Secret.Epoch))

	// Update status.
	w.mu.Lock()
	w.status.Worker.MasterSecrets.NumLoaded++
	w.status.Worker.MasterSecrets.LastLoaded = w.mstSecret.Secret.Generation
	w.mu.Unlock()

	return nil
}

func (w *secretsWorker) handleGenerateMasterSecret(ctx context.Context, height int64, epoch beacon.EpochTime) {
	if w.kmStatus == nil {
		return
	}
	if w.genMstSecInProgress || w.genMstSecRetry > generateSecretMaxRetries {
		return
	}
	if w.genSecHeight > height && len(w.kmStatus.Nodes) > 1 || w.genMstSecEpoch > epoch {
		// Observe that the height for secret generation is respected only if there are multiple
		// nodes in the key manager committee. In production, this should have no impact, but in
		// test scenarios, it allows us to transition to the next epoch earlier, as soon as all
		// required secrets are generated.
		return
	}

	// Lock. Allow only one active master secret generation.
	w.genMstSecInProgress = true

	// Master secrets are generated for the next generation and for the next epoch.
	nextGen := w.kmStatus.NextGeneration()
	nextEpoch := epoch + 1
	retry := w.genMstSecRetry

	// Retry only few times per epoch.
	w.genMstSecRetry++

	// Submitting transaction can take time, so don't block the loop.
	generateMasterSecret := func(kmStatus *secrets.Status) {
		if err := w.generateMasterSecret(ctx, w.runtimeID, height, nextGen, nextEpoch, kmStatus); err != nil {
			w.logger.Error("failed to generate master secret",
				"err", err,
				"retry", retry,
			)
			w.genMstSecDoneCh <- false
			return
		}
		w.genMstSecDoneCh <- true
	}

	go generateMasterSecret(w.kmStatus)
}

func (w *secretsWorker) generateMasterSecret(ctx context.Context, runtimeID common.Namespace, height int64, generation uint64, epoch beacon.EpochTime, kmStatus *secrets.Status) error {
	w.logger.Info("generating master secret",
		"height", height,
		"generation", generation,
		"epoch", epoch,
	)
	// Check if the master secret has been proposed in this epoch.
	// Note that despite this check, the nodes can still publish master secrets at the same time.
	lastSecret, err := w.commonWorker.Consensus.KeyManager().Secrets().GetMasterSecret(ctx, &registry.NamespaceQuery{
		Height: consensus.HeightLatest,
		ID:     runtimeID,
	})
	if err != nil && err != secrets.ErrNoSuchMasterSecret {
		return err
	}
	if lastSecret != nil && epoch == lastSecret.Secret.Epoch {
		return fmt.Errorf("master secret can be proposed once per epoch")
	}

	// Check if rotation is allowed.
	if err = kmStatus.VerifyRotationEpoch(epoch); err != nil {
		return err
	}

	// Skip generation if the node is not in the key manager committee.
	id := w.commonWorker.Identity.NodeSigner.Public()
	if !slices.Contains(kmStatus.Nodes, id) {
		w.logger.Info("skipping master secret generation, node not in the key manager committee")
		return fmt.Errorf("node not in the key manager committee")
	}

	// Generate master secret.
	args := secrets.GenerateMasterSecretRequest{
		Generation: generation,
		Epoch:      epoch,
	}

	var rsp secrets.GenerateMasterSecretResponse
	if err = w.kmWorker.callEnclaveLocal(ctx, secrets.RPCMethodGenerateMasterSecret, args, &rsp); err != nil {
		w.logger.Error("failed to generate master secret",
			"err", err,
		)
		return fmt.Errorf("failed to generate master secret: %w", err)
	}

	rak, err := w.kmWorker.runtimeAttestationKey()
	if err != nil {
		return err
	}

	reks, err := w.kmWorker.runtimeEncryptionKeys(kmStatus.Nodes)
	if err != nil {
		return err
	}

	// Verify the response.
	if err = rsp.SignedSecret.Verify(generation, epoch, reks, rak); err != nil {
		return fmt.Errorf("failed to validate master secret signature: %w", err)
	}

	// Publish transaction.
	tx := secrets.NewPublishMasterSecretTx(0, nil, &rsp.SignedSecret)
	if err = consensus.SignAndSubmitTx(ctx, w.commonWorker.Consensus, w.commonWorker.Identity.NodeSigner, tx); err != nil {
		return err
	}

	// Update metrics.
	enclaveGeneratedMasterSecretGenerationNumber.WithLabelValues(w.runtimeLabel).Set(float64(rsp.SignedSecret.Secret.Generation))
	enclaveGeneratedMasterSecretEpochNumber.WithLabelValues(w.runtimeLabel).Set(float64(rsp.SignedSecret.Secret.Epoch))

	// Update status.
	w.mu.Lock()
	w.status.Worker.MasterSecrets.NumGenerated++
	w.status.Worker.MasterSecrets.LastGenerated = rsp.SignedSecret.Secret.Generation
	w.mu.Unlock()

	return err
}

func (w *secretsWorker) handleGenerateMasterSecretDone(ok bool) {
	// Unlock.
	w.genMstSecInProgress = false

	// Disarm master secret generation if we are still in the same epoch.
	if ok && w.genMstSecRetry > 0 {
		w.genMstSecRetry = math.MaxInt64
	}
}

func (w *secretsWorker) handleNewEphemeralSecret(ctx context.Context, secret *secrets.SignedEncryptedEphemeralSecret, epoch beacon.EpochTime) {
	if !secret.Secret.ID.Equal(&w.runtimeID) {
		return
	}

	w.logger.Debug("new ephemeral secret proposed",
		"epoch", secret.Secret.Epoch,
	)

	// Update metrics.
	consensusEphemeralSecretEpochNumber.WithLabelValues(w.runtimeLabel).Set(float64(secret.Secret.Epoch))

	// Rearm ephemeral secret loading.
	w.ephSecret = secret
	w.loadEphSecRetry = 0

	if secret.Secret.Epoch == epoch+1 {
		// Disarm ephemeral secret generation.
		w.genEphSecRetry = math.MaxInt64
	}

	w.handleLoadEphemeralSecret(ctx)
}

func (w *secretsWorker) handleLoadEphemeralSecret(ctx context.Context) {
	if w.kmStatus == nil || w.ephSecret == nil {
		return
	}
	if w.loadEphSecRetry > loadSecretMaxRetries {
		return
	}

	// Retry only few times per epoch.
	w.loadEphSecRetry++

	if err := w.loadEphemeralSecret(ctx, w.ephSecret); err != nil {
		w.logger.Error("failed to load ephemeral secret",
			"err", err,
		)
		return
	}

	// Disarm ephemeral secret loading.
	w.loadEphSecRetry = math.MaxInt64
}

func (w *secretsWorker) loadEphemeralSecret(ctx context.Context, sigSecret *secrets.SignedEncryptedEphemeralSecret) error {
	w.logger.Info("loading ephemeral secret",
		"epoch", sigSecret.Secret.Epoch,
	)

	args := secrets.LoadEphemeralSecretRequest{
		SignedSecret: *sigSecret,
	}

	var rsp protocol.Empty
	if err := w.kmWorker.callEnclaveLocal(ctx, secrets.RPCMethodLoadEphemeralSecret, args, &rsp); err != nil {
		w.logger.Error("failed to load ephemeral secret",
			"err", err,
		)
		return fmt.Errorf("failed to load ephemeral secret: %w", err)
	}

	// Update metrics.
	enclaveEphemeralSecretEpochNumber.WithLabelValues(w.runtimeLabel).Set(float64(w.ephSecret.Secret.Epoch))

	// Update status.
	w.mu.Lock()
	w.status.Worker.EphemeralSecrets.NumLoaded++
	w.status.Worker.EphemeralSecrets.LastLoaded = w.ephSecret.Secret.Epoch
	w.mu.Unlock()

	return nil
}

func (w *secretsWorker) handleGenerateEphemeralSecret(ctx context.Context, height int64, epoch beacon.EpochTime) {
	if w.kmStatus == nil {
		return
	}
	if w.genEphSecInProgress || w.genEphSecRetry > generateSecretMaxRetries {
		return
	}
	if w.genSecHeight > height && len(w.kmStatus.Nodes) > 1 {
		// Observe that the height for secret generation is respected only if there are multiple
		// nodes in the key manager committee. In production, this should have no impact, but in
		// test scenarios, it allows us to transition to the next epoch earlier, as soon as all
		// required secrets are generated.
		return
	}

	// Lock. Allow only one active ephemeral secret generation.
	w.genEphSecInProgress = true

	// Ephemeral secrets are generated for the next epoch.
	nextEpoch := epoch + 1
	retry := w.genEphSecRetry

	// Retry only few times per epoch.
	w.genEphSecRetry++

	// Submitting transaction can take time, so don't block the loop.
	generateEphemeralSecret := func(kmStatus *secrets.Status) {
		if err := w.generateEphemeralSecret(ctx, w.runtimeID, height, nextEpoch, kmStatus); err != nil {
			w.logger.Error("failed to generate ephemeral secret",
				"err", err,
				"retry", retry,
			)
			w.genEphSecDoneCh <- false
			return
		}
		w.genEphSecDoneCh <- true
	}

	go generateEphemeralSecret(w.kmStatus)
}

func (w *secretsWorker) generateEphemeralSecret(ctx context.Context, runtimeID common.Namespace, height int64, epoch beacon.EpochTime, kmStatus *secrets.Status) error {
	w.logger.Info("generating ephemeral secret",
		"height", height,
		"epoch", epoch,
	)

	// Check if the ephemeral secret has been published in this epoch.
	// Note that despite this check, the nodes can still publish ephemeral secrets at the same time.
	lastSecret, err := w.commonWorker.Consensus.KeyManager().Secrets().GetEphemeralSecret(ctx, &registry.NamespaceQuery{
		Height: consensus.HeightLatest,
		ID:     runtimeID,
	})
	if err != nil && err != secrets.ErrNoSuchEphemeralSecret {
		return err
	}
	if lastSecret != nil && epoch == lastSecret.Secret.Epoch {
		return fmt.Errorf("ephemeral secret can be proposed once per epoch")
	}

	// Skip generation if the node is not in the key manager committee.
	id := w.commonWorker.Identity.NodeSigner.Public()
	if !slices.Contains(kmStatus.Nodes, id) {
		w.logger.Info("skipping ephemeral secret generation, node not in the key manager committee")
		return fmt.Errorf("node not in the key manager committee")
	}

	// Generate ephemeral secret.
	args := secrets.GenerateEphemeralSecretRequest{
		Epoch: epoch,
	}

	var rsp secrets.GenerateEphemeralSecretResponse
	if err = w.kmWorker.callEnclaveLocal(ctx, secrets.RPCMethodGenerateEphemeralSecret, args, &rsp); err != nil {
		w.logger.Error("failed to generate ephemeral secret",
			"err", err,
		)
		return fmt.Errorf("failed to generate ephemeral secret: %w", err)
	}

	rak, err := w.kmWorker.runtimeAttestationKey()
	if err != nil {
		return err
	}

	reks, err := w.kmWorker.runtimeEncryptionKeys(kmStatus.Nodes)
	if err != nil {
		return err
	}

	// Verify the response.
	if err = rsp.SignedSecret.Verify(epoch, reks, rak); err != nil {
		return fmt.Errorf("failed to validate ephemeral secret signature: %w", err)
	}

	// Publish transaction.
	tx := secrets.NewPublishEphemeralSecretTx(0, nil, &rsp.SignedSecret)
	if err = consensus.SignAndSubmitTx(ctx, w.commonWorker.Consensus, w.commonWorker.Identity.NodeSigner, tx); err != nil {
		return err
	}

	// Update metrics.
	enclaveGeneratedEphemeralSecretEpochNumber.WithLabelValues(w.runtimeLabel).Set(float64(rsp.SignedSecret.Secret.Epoch))

	// Update status.
	w.mu.Lock()
	w.status.Worker.EphemeralSecrets.NumGenerated++
	w.status.Worker.EphemeralSecrets.LastGenerated = rsp.SignedSecret.Secret.Epoch
	w.mu.Unlock()

	return err
}

func (w *secretsWorker) handleGenerateEphemeralSecretDone(ok bool) {
	// Unlock.
	w.genEphSecInProgress = false

	// Disarm ephemeral secret generation if we are still in the same epoch.
	if ok && w.genEphSecRetry > 0 {
		w.genEphSecRetry = math.MaxInt64
	}
}
