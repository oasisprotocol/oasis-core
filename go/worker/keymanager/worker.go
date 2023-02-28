package keymanager

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/libp2p/go-libp2p/core"
	"golang.org/x/exp/slices"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	workerKeymanager "github.com/oasisprotocol/oasis-core/go/worker/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

const (
	rpcCallTimeout = 2 * time.Second

	generateSecretMaxRetries = 5
	loadSecretMaxRetries     = 5
	ephemeralSecretCacheSize = 20
)

var (
	_ service.BackgroundService = (*Worker)(nil)

	errMalformedResponse = fmt.Errorf("worker/keymanager: malformed response from worker")
)

type runtimeStatus struct {
	version       version.Version
	capabilityTEE *node.CapabilityTEE
}

// Worker is the key manager worker.
//
// It behaves differently from other workers as the key manager has its
// own runtime. It needs to keep track of executor committees for other
// runtimes in order to update the access control lists.
type Worker struct { // nolint: maligned
	sync.RWMutex
	*runtimeRegistry.RuntimeHostNode

	logger *logging.Logger

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	quitCh    chan struct{}
	initCh    chan struct{}

	runtime   runtimeRegistry.Runtime
	runtimeID common.Namespace

	clientRuntimes map[common.Namespace]*clientRuntimeWatcher

	accessList          map[core.PeerID]map[common.Namespace]struct{}
	accessListByRuntime map[common.Namespace][]core.PeerID
	privatePeers        map[core.PeerID]struct{}

	commonWorker *workerCommon.Worker
	roleProvider registration.RoleProvider
	backend      api.Backend

	globalStatus  *api.Status
	enclaveStatus *api.SignedInitResponse
	policy        *api.SignedPolicySGX

	masterSecretStats    workerKeymanager.MasterSecretStats
	ephemeralSecretStats workerKeymanager.EphemeralSecretStats

	enabled     bool
	mayGenerate bool

	kmStatus *api.Status
	rtStatus *runtimeStatus

	initEnclaveInProgress  bool
	initEnclaveRequired    bool
	initEnclaveDoneCh      chan *api.SignedInitResponse
	initEnclaveRetryCh     <-chan time.Time
	initEnclaveRetryTicker *backoff.Ticker

	mstSecret *api.SignedEncryptedMasterSecret

	loadMstSecRetry     int
	genMstSecDoneCh     chan bool
	genMstSecEpoch      beacon.EpochTime
	genMstSecInProgress bool
	genMstSecRetry      int

	ephSecrets []*api.SignedEncryptedEphemeralSecret

	loadEphSecRetry     int
	genEphSecDoneCh     chan bool
	genEphSecInProgress bool
	genEphSecRetry      int

	genSecHeight int64
}

func (w *Worker) Name() string {
	return "key manager worker"
}

func (w *Worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting key manager worker as it is disabled")
		close(w.initCh)

		return nil
	}

	go w.worker()

	return nil
}

func (w *Worker) Stop() {
	w.logger.Info("stopping key manager service")

	if !w.enabled {
		close(w.quitCh)
		return
	}

	// Stop the sub-components.
	w.cancelCtx()
	close(w.stopCh)
}

// Enabled returns if worker is enabled.
func (w *Worker) Enabled() bool {
	return w.enabled
}

func (w *Worker) Quit() <-chan struct{} {
	return w.quitCh
}

func (w *Worker) Cleanup() {
}

// Initialized returns a channel that will be closed when the worker is initialized, ready to
// service requests and registered with the consensus layer.
func (w *Worker) Initialized() <-chan struct{} {
	return w.initCh
}

func (w *Worker) CallEnclave(ctx context.Context, data []byte, kind enclaverpc.Kind) ([]byte, error) {
	select {
	case <-w.initCh:
	default:
		return nil, fmt.Errorf("not initialized")
	}

	switch kind {
	case enclaverpc.KindNoiseSession:
		// Handle access control as only peers on the access list can call this method.
		peerID, ok := rpc.PeerIDFromContext(ctx)
		if !ok {
			return nil, fmt.Errorf("not authorized")
		}

		// Peek into the frame data to extract the method.
		var frame enclaverpc.Frame
		if err := cbor.Unmarshal(data, &frame); err != nil {
			return nil, fmt.Errorf("malformed request")
		}

		// Note that the untrusted plaintext is also checked in the enclave, so if the node lied about
		// what method it's using, we will know and the request will get rejected.
		switch frame.UntrustedPlaintext {
		case "":
			// Anyone can connect.
		case api.RPCMethodGetPublicKey, api.RPCMethodGetPublicEphemeralKey:
			// Anyone can get public keys.
		default:
			if _, privatePeered := w.privatePeers[peerID]; !privatePeered {
				// Defer to access control to check the policy.
				w.RLock()
				_, allowed := w.accessList[peerID]
				w.RUnlock()
				if !allowed {
					return nil, fmt.Errorf("not authorized")
				}
			}
		}
	case enclaverpc.KindInsecureQuery:
		// Insecure queries are always allowed.
	default:
		// Local queries are not allowed.
		return nil, fmt.Errorf("unsupported RPC kind")
	}

	ctx, cancel := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancel()

	req := &protocol.Body{
		RuntimeRPCCallRequest: &protocol.RuntimeRPCCallRequest{
			Request: data,
			Kind:    kind,
		},
	}

	// Hosted runtime should not be nil as we are initialized.
	rt := w.GetHostedRuntime()
	response, err := rt.Call(ctx, req)
	if err != nil {
		w.logger.Error("failed to dispatch RPC call to runtime",
			"err", err,
		)
		return nil, err
	}

	resp := response.RuntimeRPCCallResponse
	if resp == nil {
		w.logger.Error("malformed response from runtime",
			"response", response,
		)
		return nil, errMalformedResponse
	}

	return resp.Response, nil
}

func (w *Worker) localCallEnclave(method string, args interface{}, rsp interface{}) error {
	req := enclaverpc.Request{
		Method: method,
		Args:   args,
	}
	body := &protocol.Body{
		RuntimeLocalRPCCallRequest: &protocol.RuntimeLocalRPCCallRequest{
			Request: cbor.Marshal(&req),
		},
	}

	rt := w.GetHostedRuntime()
	response, err := rt.Call(w.ctx, body)
	if err != nil {
		w.logger.Error("failed to dispatch local RPC call to runtime",
			"method", method,
			"err", err,
		)
		return err
	}

	resp := response.RuntimeLocalRPCCallResponse
	if resp == nil {
		w.logger.Error("malformed response from runtime",
			"method", method,
			"response", response,
		)
		return errMalformedResponse
	}

	var msg enclaverpc.Message
	if err = cbor.Unmarshal(resp.Response, &msg); err != nil {
		return fmt.Errorf("malformed message envelope: %w", err)
	}

	if msg.Response == nil {
		return fmt.Errorf("message is not a response: '%s'", hex.EncodeToString(resp.Response))
	}

	switch {
	case msg.Response.Body.Success != nil:
	case msg.Response.Body.Error != nil:
		return fmt.Errorf("rpc failure: '%s'", *msg.Response.Body.Error)
	default:
		return fmt.Errorf("unknown rpc response status: '%s'", hex.EncodeToString(resp.Response))
	}

	if err = cbor.Unmarshal(msg.Response.Body.Success, rsp); err != nil {
		return fmt.Errorf("failed to extract rpc response payload: %w", err)
	}

	return nil
}

func (w *Worker) initEnclave(kmStatus *api.Status, rtStatus *runtimeStatus) (*api.SignedInitResponse, error) {
	w.logger.Info("initializing key manager enclave")

	// Check if the key manager supports init requests with key manager status
	// field which were deployed together with master secret rotation feature.
	// TODO: Remove in PR-5205.
	rt := w.GetHostedRuntime()
	if rt == nil {
		w.logger.Warn("runtime is not yet ready")
		return nil, fmt.Errorf("worker/keymanager: runtime is not yet ready")
	}
	rtInfo, err := rt.GetInfo(w.ctx)
	if err != nil {
		w.logger.Warn("runtime is broken",
			"err", err,
		)
		return nil, fmt.Errorf("worker/keymanager: runtime is broken")
	}

	// Initialize the key manager.
	var args api.InitRequest
	if rtInfo.Features != nil && rtInfo.Features.KeyManagerMasterSecretRotation {
		args = api.InitRequest{
			Status: kmStatus,
		}
	} else {
		var policy []byte
		if kmStatus.Policy != nil {
			policy = cbor.Marshal(kmStatus.Policy)
		}

		args = api.InitRequest{
			Checksum:    kmStatus.Checksum,
			Policy:      policy,
			MayGenerate: w.mayGenerate,
		}
	}

	var signedInitResp api.SignedInitResponse
	if err := w.localCallEnclave(api.RPCMethodInit, args, &signedInitResp); err != nil {
		w.logger.Error("failed to initialize enclave",
			"err", err,
		)
		return nil, fmt.Errorf("worker/keymanager: failed to initialize enclave: %w", err)
	}

	// Validate the signature.
	if tee := rtStatus.capabilityTEE; tee != nil {
		var signingKey signature.PublicKey

		switch tee.Hardware {
		case node.TEEHardwareInvalid:
			signingKey = api.InsecureRAK
		case node.TEEHardwareIntelSGX:
			signingKey = tee.RAK
		default:
			return nil, fmt.Errorf("worker/keymanager: unknown TEE hardware: %v", tee.Hardware)
		}

		if err := signedInitResp.Verify(signingKey); err != nil {
			return nil, fmt.Errorf("worker/keymanager: failed to validate initialization response signature: %w", err)
		}
	}

	if !signedInitResp.InitResponse.IsSecure {
		w.logger.Warn("key manager enclave build is INSECURE")
	}

	w.logger.Info("key manager enclave initialized",
		"is_secure", signedInitResp.InitResponse.IsSecure,
		"checksum", hex.EncodeToString(signedInitResp.InitResponse.Checksum),
		"next_checksum", hex.EncodeToString(signedInitResp.InitResponse.NextChecksum),
		"policy_checksum", hex.EncodeToString(signedInitResp.InitResponse.PolicyChecksum),
		"rsk", signedInitResp.InitResponse.RSK,
		"next_rsk", signedInitResp.InitResponse.NextRSK,
	)

	// Cache the key manager enclave status and the currently active policy.
	w.Lock()
	defer w.Unlock()

	if w.enclaveStatus == nil || !bytes.Equal(w.enclaveStatus.InitResponse.PolicyChecksum, signedInitResp.InitResponse.PolicyChecksum) {
		policyUpdateCount.Inc()
	}

	w.enclaveStatus = &signedInitResp
	w.policy = kmStatus.Policy

	return &signedInitResp, nil
}

func (w *Worker) registerNode(rsp *api.SignedInitResponse) {
	w.logger.Info("registering key manager",
		"is_secure", rsp.InitResponse.IsSecure,
		"checksum", hex.EncodeToString(rsp.InitResponse.Checksum),
		"policy_checksum", hex.EncodeToString(rsp.InitResponse.PolicyChecksum),
		"rsk", rsp.InitResponse.RSK,
		"next_rsk", rsp.InitResponse.NextRSK,
	)

	// Register as we are now ready to handle requests.
	rtStatus := w.rtStatus
	extraInfo := cbor.Marshal(rsp)
	w.roleProvider.SetAvailableWithCallback(func(n *node.Node) error {
		rt := n.AddOrUpdateRuntime(w.runtimeID, rtStatus.version)
		rt.Version = rtStatus.version
		rt.ExtraInfo = extraInfo
		rt.Capabilities.TEE = rtStatus.capabilityTEE
		return nil
	}, func(context.Context) error {
		w.logger.Info("key manager registered")

		// Signal that we are initialized.
		select {
		case <-w.initCh:
		default:
			w.logger.Info("key manager initialized")
			close(w.initCh)
		}

		return nil
	})
}

func (w *Worker) setStatus(status *api.Status) {
	w.Lock()
	defer w.Unlock()

	w.globalStatus = status
}

func (w *Worker) setLastGeneratedMasterSecretGeneration(generation uint64) {
	w.Lock()
	defer w.Unlock()

	w.masterSecretStats.NumGenerated++
	w.masterSecretStats.LastGenerated = generation
}

func (w *Worker) setLastLoadedMasterSecretGeneration(generation uint64) {
	w.Lock()
	defer w.Unlock()

	w.masterSecretStats.NumLoaded++
	w.masterSecretStats.LastLoaded = generation
}

func (w *Worker) setLastGeneratedEphemeralSecretEpoch(epoch beacon.EpochTime) {
	w.Lock()
	defer w.Unlock()

	w.ephemeralSecretStats.NumGenerated++
	w.ephemeralSecretStats.LastGenerated = epoch
}

func (w *Worker) setLastLoadedEphemeralSecretEpoch(epoch beacon.EpochTime) {
	w.Lock()
	defer w.Unlock()

	w.ephemeralSecretStats.NumLoaded++
	w.ephemeralSecretStats.LastLoaded = epoch
}

func (w *Worker) addClientRuntimeWatcher(n common.Namespace, crw *clientRuntimeWatcher) {
	w.Lock()
	defer w.Unlock()

	w.clientRuntimes[n] = crw
}

func (w *Worker) getClientRuntimeWatcher(n common.Namespace) *clientRuntimeWatcher {
	w.RLock()
	defer w.RUnlock()

	return w.clientRuntimes[n]
}

func (w *Worker) getClientRuntimeWatchers() []*clientRuntimeWatcher {
	w.RLock()
	defer w.RUnlock()

	crws := make([]*clientRuntimeWatcher, 0, len(w.clientRuntimes))
	for _, crw := range w.clientRuntimes {
		crws = append(crws, crw)
	}

	return crws
}

func (w *Worker) startClientRuntimeWatcher(rt *registry.Runtime, kmStatus *api.Status) error {
	if kmStatus == nil || !kmStatus.IsInitialized || w.rtStatus == nil {
		return nil
	}
	if rt.Kind != registry.KindCompute || rt.KeyManager == nil || !rt.KeyManager.Equal(&w.runtimeID) {
		return nil
	}
	if w.getClientRuntimeWatcher(rt.ID) != nil {
		return nil
	}

	w.logger.Info("seen new runtime using us as a key manager",
		"runtime_id", rt.ID,
	)

	// Check policy document if runtime is allowed to query any of the
	// key manager enclaves.
	var allowed bool
	switch {
	case w.rtStatus.capabilityTEE == nil:
		// Insecure test key manager enclaves can be queried by all runtimes.
		allowed = !kmStatus.IsSecure
	case w.rtStatus.capabilityTEE.Hardware == node.TEEHardwareIntelSGX:
		if kmStatus.Policy == nil {
			break
		}
		for _, enc := range kmStatus.Policy.Policy.Enclaves {
			if _, ok := enc.MayQuery[rt.ID]; ok {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		w.logger.Warn("runtime not found in keymanager policy, skipping",
			"runtime_id", rt.ID,
			"status", kmStatus,
		)
		return nil
	}

	nodes, err := nodes.NewVersionedNodeDescriptorWatcher(w.ctx, w.commonWorker.Consensus)
	if err != nil {
		w.logger.Error("unable to create new client runtime node watcher",
			"err", err,
			"runtime_id", rt.ID,
		)
		return err
	}
	crw := &clientRuntimeWatcher{
		w:         w,
		runtimeID: rt.ID,
		nodes:     nodes,
	}
	crw.epochTransition()
	go crw.worker()

	w.addClientRuntimeWatcher(rt.ID, crw)

	computeRuntimeCount.Inc()

	return nil
}

func (w *Worker) recheckAllRuntimes(kmStatus *api.Status) error {
	rts, err := w.commonWorker.Consensus.Registry().GetRuntimes(w.ctx,
		&registry.GetRuntimesQuery{
			Height:           consensus.HeightLatest,
			IncludeSuspended: false,
		},
	)
	if err != nil {
		w.logger.Error("failed querying runtimes",
			"err", err,
		)
		return fmt.Errorf("failed querying runtimes: %w", err)
	}
	for _, rt := range rts {
		if err := w.startClientRuntimeWatcher(rt, kmStatus); err != nil {
			w.logger.Error("failed to start runtime watcher",
				"err", err,
			)
			continue
		}
	}

	return nil
}

func (w *Worker) setAccessList(runtimeID common.Namespace, nodes []*node.Node) {
	w.Lock()
	defer w.Unlock()

	// Clear any old nodes from the access list.
	for _, peerID := range w.accessListByRuntime[runtimeID] {
		entry := w.accessList[peerID]
		delete(entry, runtimeID)
		if len(entry) == 0 {
			delete(w.accessList, peerID)
		}
	}

	// Update the access list.
	var peers []core.PeerID
	for _, node := range nodes {
		peerID, err := p2p.PublicKeyToPeerID(node.P2P.ID)
		if err != nil {
			w.logger.Warn("invalid node P2P ID",
				"err", err,
				"node_id", node.ID,
			)
			continue
		}

		entry := w.accessList[peerID]
		if entry == nil {
			entry = make(map[common.Namespace]struct{})
			w.accessList[peerID] = entry
		}

		entry[runtimeID] = struct{}{}
		peers = append(peers, peerID)
	}
	w.accessListByRuntime[runtimeID] = peers

	w.logger.Debug("new client runtime access policy in effect",
		"runtime_id", runtimeID,
		"peers", peers,
	)
}

func (w *Worker) generateMasterSecret(runtimeID common.Namespace, generation uint64, epoch beacon.EpochTime, kmStatus *api.Status, rtStatus *runtimeStatus) error {
	w.logger.Info("generating master secret",
		"generation", generation,
		"epoch", epoch,
	)
	// Check if the master secret has been proposed in this epoch.
	// Note that despite this check, the nodes can still publish master secrets at the same time.
	lastSecret, err := w.commonWorker.Consensus.KeyManager().GetMasterSecret(w.ctx, &registry.NamespaceQuery{
		Height: consensus.HeightLatest,
		ID:     runtimeID,
	})
	if err != nil && err != api.ErrNoSuchMasterSecret {
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
	args := api.GenerateMasterSecretRequest{
		Generation: generation,
		Epoch:      epoch,
	}

	var rsp api.GenerateMasterSecretResponse
	if err = w.localCallEnclave(api.RPCMethodGenerateMasterSecret, args, &rsp); err != nil {
		w.logger.Error("failed to generate master secret",
			"err", err,
		)
		return fmt.Errorf("failed to generate master secret: %w", err)
	}

	// Fetch key manager runtime details.
	kmRt, err := w.commonWorker.Consensus.Registry().GetRuntime(w.ctx, &registry.GetRuntimeQuery{
		Height: consensus.HeightLatest,
		ID:     kmStatus.ID,
	})
	if err != nil {
		return err
	}

	rak, err := w.runtimeAttestationKey(rtStatus, kmRt)
	if err != nil {
		return err
	}

	reks, err := w.runtimeEncryptionKeys(kmStatus, kmRt)
	if err != nil {
		return err
	}

	// Verify the response.
	if err = rsp.SignedSecret.Verify(generation, epoch, reks, rak); err != nil {
		return fmt.Errorf("failed to validate master secret signature: %w", err)
	}

	// Publish transaction.
	tx := api.NewPublishMasterSecretTx(0, nil, &rsp.SignedSecret)
	if err = consensus.SignAndSubmitTx(w.ctx, w.commonWorker.Consensus, w.commonWorker.Identity.NodeSigner, tx); err != nil {
		return err
	}

	return err
}

func (w *Worker) generateEphemeralSecret(runtimeID common.Namespace, epoch beacon.EpochTime, kmStatus *api.Status, rtStatus *runtimeStatus) error {
	w.logger.Info("generating ephemeral secret",
		"epoch", epoch,
	)

	// Check if the ephemeral secret has been published in this epoch.
	// Note that despite this check, the nodes can still publish ephemeral secrets at the same time.
	_, err := w.commonWorker.Consensus.KeyManager().GetEphemeralSecret(w.ctx, &registry.NamespaceEpochQuery{
		Height: consensus.HeightLatest,
		ID:     runtimeID,
		Epoch:  epoch,
	})
	switch err {
	case nil:
		w.logger.Info("skipping secret generation, ephemeral secret already published")
		return nil
	case api.ErrNoSuchEphemeralSecret:
		// Secret hasn't been published.
	default:
		w.logger.Error("failed to fetch ephemeral secret",
			"err", err,
		)
		return fmt.Errorf("failed to fetch ephemeral secret: %w", err)
	}

	// Skip generation if the node is not in the key manager committee.
	id := w.commonWorker.Identity.NodeSigner.Public()
	if !slices.Contains(kmStatus.Nodes, id) {
		w.logger.Info("skipping ephemeral secret generation, node not in the key manager committee")
		return fmt.Errorf("node not in the key manager committee")
	}

	// Generate ephemeral secret.
	args := api.GenerateEphemeralSecretRequest{
		Epoch: epoch,
	}

	var rsp api.GenerateEphemeralSecretResponse
	if err = w.localCallEnclave(api.RPCMethodGenerateEphemeralSecret, args, &rsp); err != nil {
		w.logger.Error("failed to generate ephemeral secret",
			"err", err,
		)
		return fmt.Errorf("failed to generate ephemeral secret: %w", err)
	}

	// Fetch key manager runtime details.
	kmRt, err := w.commonWorker.Consensus.Registry().GetRuntime(w.ctx, &registry.GetRuntimeQuery{
		Height: consensus.HeightLatest,
		ID:     kmStatus.ID,
	})
	if err != nil {
		return err
	}

	rak, err := w.runtimeAttestationKey(rtStatus, kmRt)
	if err != nil {
		return err
	}

	reks, err := w.runtimeEncryptionKeys(kmStatus, kmRt)
	if err != nil {
		return err
	}

	// Verify the response.
	if err = rsp.SignedSecret.Verify(epoch, reks, rak); err != nil {
		return fmt.Errorf("failed to validate ephemeral secret signature: %w", err)
	}

	// Publish transaction.
	tx := api.NewPublishEphemeralSecretTx(0, nil, &rsp.SignedSecret)
	if err = consensus.SignAndSubmitTx(w.ctx, w.commonWorker.Consensus, w.commonWorker.Identity.NodeSigner, tx); err != nil {
		return err
	}

	return err
}

func (w *Worker) runtimeAttestationKey(rtStatus *runtimeStatus, kmRt *registry.Runtime) (*signature.PublicKey, error) {
	var rak *signature.PublicKey
	switch kmRt.TEEHardware {
	case node.TEEHardwareInvalid:
		rak = &api.InsecureRAK
	case node.TEEHardwareIntelSGX:
		if rtStatus.capabilityTEE == nil {
			return nil, fmt.Errorf("node doesn't have TEE capability")
		}
		rak = &rtStatus.capabilityTEE.RAK
	default:
		return nil, fmt.Errorf("TEE hardware mismatch")
	}

	return rak, nil
}

func (w *Worker) runtimeEncryptionKeys(kmStatus *api.Status, kmRt *registry.Runtime) (map[x25519.PublicKey]struct{}, error) {
	reks := make(map[x25519.PublicKey]struct{})
	for _, id := range kmStatus.Nodes {
		var n *node.Node
		n, err := w.commonWorker.Consensus.Registry().GetNode(w.ctx, &registry.IDQuery{
			Height: consensus.HeightLatest,
			ID:     id,
		})
		switch err {
		case nil:
		case registry.ErrNoSuchNode:
			continue
		default:
			return nil, err
		}

		idx := slices.IndexFunc(n.Runtimes, func(rt *node.Runtime) bool {
			// Skipping version check as key managers are running exactly one
			// version of the runtime.
			return rt.ID.Equal(&kmStatus.ID)
		})
		if idx == -1 {
			continue
		}
		nRt := n.Runtimes[idx]

		var rek x25519.PublicKey
		switch kmRt.TEEHardware {
		case node.TEEHardwareInvalid:
			rek = api.InsecureREK
		case node.TEEHardwareIntelSGX:
			if nRt.Capabilities.TEE == nil || nRt.Capabilities.TEE.REK == nil {
				continue
			}
			rek = *nRt.Capabilities.TEE.REK
		default:
			continue
		}

		reks[rek] = struct{}{}
	}

	return reks, nil
}

func (w *Worker) loadMasterSecret(sigSecret *api.SignedEncryptedMasterSecret) error {
	w.logger.Info("loading master secret",
		"generation", sigSecret.Secret.Generation,
		"epoch", sigSecret.Secret.Epoch,
	)

	args := api.LoadMasterSecretRequest{
		SignedSecret: *sigSecret,
	}

	var rsp protocol.Empty
	if err := w.localCallEnclave(api.RPCMethodLoadMasterSecret, args, &rsp); err != nil {
		w.logger.Error("failed to load master secret",
			"err", err,
		)
		return fmt.Errorf("failed to load master secret: %w", err)
	}

	return nil
}

func (w *Worker) loadEphemeralSecret(sigSecret *api.SignedEncryptedEphemeralSecret) error {
	w.logger.Info("loading ephemeral secret",
		"epoch", sigSecret.Secret.Epoch,
	)

	args := api.LoadEphemeralSecretRequest{
		SignedSecret: *sigSecret,
	}

	var rsp protocol.Empty
	if err := w.localCallEnclave(api.RPCMethodLoadEphemeralSecret, args, &rsp); err != nil {
		w.logger.Error("failed to load ephemeral secret",
			"err", err,
		)
		return fmt.Errorf("failed to load ephemeral secret: %w", err)
	}

	return nil
}

func (w *Worker) fetchLastEphemeralSecrets(runtimeID common.Namespace) ([]*api.SignedEncryptedEphemeralSecret, error) {
	w.logger.Info("fetching last ephemeral secrets")

	// Get next epoch.
	epoch, err := w.commonWorker.Consensus.Beacon().GetEpoch(w.ctx, consensus.HeightLatest)
	if err != nil {
		w.logger.Error("failed to fetch epoch",
			"err", err,
		)
		return nil, fmt.Errorf("failed to fetch epoch: %w", err)
	}
	epoch++

	// Fetch last few ephemeral secrets.
	N := ephemeralSecretCacheSize
	secrets := make([]*api.SignedEncryptedEphemeralSecret, 0, N)
	for i := 0; i < N && epoch > 0; i, epoch = i+1, epoch-1 {
		secret, err := w.commonWorker.Consensus.KeyManager().GetEphemeralSecret(w.ctx, &registry.NamespaceEpochQuery{
			Height: consensus.HeightLatest,
			ID:     runtimeID,
			Epoch:  epoch,
		})

		switch err {
		case nil:
			secrets = append(secrets, secret)
		case api.ErrNoSuchEphemeralSecret:
			// Secret hasn't been published.
		default:
			w.logger.Error("failed to fetch ephemeral secret",
				"err", err,
			)
			return nil, fmt.Errorf("failed to fetch ephemeral secret: %w", err)
		}
	}

	return secrets, nil
}

// randomBlockHeight returns the height of a random block in the k-th percentile of the given epoch.
func (w *Worker) randomBlockHeight(epoch beacon.EpochTime, percentile int64) (int64, error) {
	// Get height of the first block.
	params, err := w.commonWorker.Consensus.Beacon().ConsensusParameters(w.ctx, consensus.HeightLatest)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
	first, err := w.commonWorker.Consensus.Beacon().GetEpochBlock(w.ctx, epoch)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch epoch block height: %w", err)
	}

	// Pick a random height from the given percentile.
	interval := params.Interval()
	if percentile < 100 {
		interval = interval * percentile / 100
	}
	if interval <= 0 {
		interval = 1
	}
	height := first + rand.Int63n(interval)

	return height, nil
}

func (w *Worker) updateGenerateMasterSecretEpoch() {
	var nextEpoch beacon.EpochTime

	// If at least one master secret has been generated, respect the rotation interval.
	nextGen := w.kmStatus.NextGeneration()
	if nextGen != 0 {
		// Disable rotation if the policy is not set.
		var rotationInterval beacon.EpochTime
		if w.kmStatus.Policy != nil {
			rotationInterval = w.kmStatus.Policy.Policy.MasterSecretRotationInterval
		}

		// Secrets are allowed to be generated at most one epoch before the rotation.
		nextEpoch = w.kmStatus.RotationEpoch + rotationInterval - 1

		// Rotation not allowed.
		if rotationInterval == 0 {
			nextEpoch = math.MaxUint64
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

func (w *Worker) handleStatusUpdate(kmStatus *api.Status) {
	if kmStatus == nil || !kmStatus.ID.Equal(&w.runtimeID) {
		return
	}

	w.logger.Debug("key manager status updated",
		"generation", kmStatus.Generation,
		"rotation_epoch", kmStatus.RotationEpoch,
		"checksum", hex.EncodeToString(kmStatus.Checksum),
	)

	// Cache the latest status.
	w.setStatus(kmStatus)
	w.kmStatus = kmStatus

	// (Re)Initialize the enclave.
	// A new master secret generation or policy might have been published.
	w.handleInitEnclave()

	// New runtimes can be allowed with the policy update.
	if err := w.recheckAllRuntimes(w.kmStatus); err != nil {
		w.logger.Error("failed rechecking runtimes",
			"err", err,
		)
	}

	// The epoch for generating the next master secret may change with the policy update.
	w.updateGenerateMasterSecretEpoch()
}

func (w *Worker) handleInitEnclave() {
	if w.kmStatus == nil || w.rtStatus == nil {
		// There's no need to retry as another call will be made
		// once both fields are initialized.
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
	initEnclave := func(kmStatus *api.Status, rtStatus *runtimeStatus) {
		rsp, err := w.initEnclave(kmStatus, rtStatus)
		if err != nil {
			w.logger.Error("failed to initialize enclave",
				"err", err,
			)
		}
		w.initEnclaveDoneCh <- rsp
	}

	go initEnclave(w.kmStatus, w.rtStatus)
}

func (w *Worker) handleInitEnclaveDone(rsp *api.SignedInitResponse) {
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
		w.handleInitEnclave()
		return
	}

	// (Re)Register the node with the latest init response.
	if rsp != nil {
		w.registerNode(rsp)
	}
}

func (w *Worker) handleRuntimeHostEvent(ev *host.Event) {
	switch {
	case ev.Started != nil, ev.Updated != nil:
		// Runtime has started successfully.
		w.rtStatus = &runtimeStatus{}
		switch {
		case ev.Started != nil:
			w.rtStatus.version = ev.Started.Version
			w.rtStatus.capabilityTEE = ev.Started.CapabilityTEE
		case ev.Updated != nil:
			w.rtStatus.version = ev.Updated.Version
			w.rtStatus.capabilityTEE = ev.Updated.CapabilityTEE
		default:
			return
		}

		// Fetch last few ephemeral secrets and load them.
		var err error
		w.ephSecrets, err = w.fetchLastEphemeralSecrets(w.runtimeID)
		if err != nil {
			w.logger.Error("failed to fetch last ephemeral secrets",
				"err", err,
			)
		}
		w.loadEphSecRetry = 0
		w.handleLoadEphemeralSecret()

		if w.kmStatus == nil {
			return
		}

		// Send a node preregistration, so that other nodes know to update their access
		// control. Without it, the enclave won't be able to replicate the master secrets
		// needed for initialization.
		if w.enclaveStatus == nil {
			w.roleProvider.SetAvailableWithCallback(func(n *node.Node) error {
				rt := n.AddOrUpdateRuntime(w.runtime.ID(), w.rtStatus.version)
				rt.Version = w.rtStatus.version
				rt.ExtraInfo = nil
				rt.Capabilities.TEE = w.rtStatus.capabilityTEE
				return nil
			}, func(context.Context) error {
				w.logger.Info("key manager registered (pre-registration)")
				return nil
			})
		}

		w.handleStatusUpdate(w.kmStatus)
	case ev.FailedToStart != nil, ev.Stopped != nil:
		// Worker failed to start or was stopped -- we can no longer service requests.
		w.rtStatus = nil
		w.roleProvider.SetUnavailable()
	default:
		// Unknown event.
		w.logger.Warn("unknown worker event",
			"ev", ev,
		)
	}
}

func (w *Worker) handleRuntimeRegistrationEvent(rt *registry.Runtime) {
	if err := w.startClientRuntimeWatcher(rt, w.kmStatus); err != nil {
		w.logger.Error("failed to start runtime watcher",
			"err", err,
		)
		return
	}
}

func (w *Worker) handleNewEpoch(epoch beacon.EpochTime) {
	// Update per runtime access lists.
	for _, crw := range w.getClientRuntimeWatchers() {
		crw.epochTransition()
	}

	// Choose a random height for generating master/ephemeral secrets.
	// Avoid blocks at the end of the epoch as secret generation,
	// publication and replication takes some time.
	height, err := w.randomBlockHeight(epoch, 50)
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

func (w *Worker) handleNewBlock(blk *consensus.Block, epoch beacon.EpochTime) {
	if blk == nil {
		w.logger.Error("watch blocks channel closed unexpectedly")
		return
	}

	// (Re)Generate master/ephemeral secrets once we reach the chosen height and epoch.
	w.handleGenerateMasterSecret(blk.Height, epoch)
	w.handleGenerateEphemeralSecret(blk.Height, epoch)

	// (Re)Load master/ephemeral secrets.
	// When using CometBFT as a backend service the first load
	// will probably fail as the verifier is one block behind.
	w.handleLoadMasterSecret()
	w.handleLoadEphemeralSecret()
}

func (w *Worker) handleNewMasterSecret(secret *api.SignedEncryptedMasterSecret) {
	if !secret.Secret.ID.Equal(&w.runtimeID) {
		return
	}

	w.logger.Debug("master secret published",
		"generation", secret.Secret.Generation,
		"epoch", secret.Secret.Epoch,
		"checksum", hex.EncodeToString(secret.Secret.Secret.Checksum),
	)

	w.mstSecret = secret
	w.loadMstSecRetry = 0

	w.updateGenerateMasterSecretEpoch()
	w.handleLoadMasterSecret()
}

func (w *Worker) handleGenerateMasterSecret(height int64, epoch beacon.EpochTime) {
	if w.kmStatus == nil || w.rtStatus == nil {
		return
	}
	if w.genMstSecInProgress || w.genMstSecRetry > generateSecretMaxRetries {
		return
	}
	if w.genSecHeight > height || w.genMstSecEpoch > epoch {
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
	generateMasterSecret := func(kmStatus *api.Status, rtStatus *runtimeStatus) {
		if err := w.generateMasterSecret(w.runtimeID, nextGen, nextEpoch, kmStatus, rtStatus); err != nil {
			w.logger.Error("failed to generate master secret",
				"err", err,
				"retry", retry,
			)
			w.genMstSecDoneCh <- false
			return
		}

		w.setLastGeneratedMasterSecretGeneration(nextGen)
		w.genMstSecDoneCh <- true
	}

	go generateMasterSecret(w.kmStatus, w.rtStatus)
}

func (w *Worker) handleGenerateMasterSecretDone(ok bool) {
	// Unlock.
	w.genMstSecInProgress = false

	// Disarm master secret generation if we are still in the same epoch.
	if ok && w.genMstSecRetry > 0 {
		w.genMstSecRetry = math.MaxInt64
	}
}

func (w *Worker) handleLoadMasterSecret() {
	if w.kmStatus == nil || w.rtStatus == nil || w.mstSecret == nil {
		return
	}
	if w.loadMstSecRetry > loadSecretMaxRetries {
		return
	}

	// Retry only few times per epoch.
	w.loadMstSecRetry++

	if err := w.loadMasterSecret(w.mstSecret); err != nil {
		w.logger.Error("failed to load master secret",
			"err", err,
			"retry", w.loadMstSecRetry-1,
		)
		return
	}

	// Disarm master secret loading.
	w.loadMstSecRetry = math.MaxInt64
	w.setLastLoadedMasterSecretGeneration(w.mstSecret.Secret.Generation)

	// Announce that the enclave has replicated the proposal for the next master
	// secret and is ready for rotation.
	w.handleInitEnclave()
}

func (w *Worker) handleNewEphemeralSecret(secret *api.SignedEncryptedEphemeralSecret, epoch beacon.EpochTime) {
	if !secret.Secret.ID.Equal(&w.runtimeID) {
		return
	}

	w.logger.Debug("ephemeral secret published",
		"epoch", secret.Secret.Epoch,
	)

	if secret.Secret.Epoch == epoch+1 {
		// Disarm ephemeral secret generation.
		w.genEphSecRetry = math.MaxInt64
	}

	// Add secret to the list and send a signal to load it.
	w.ephSecrets = append(w.ephSecrets, secret)
	w.loadEphSecRetry = 0

	w.handleLoadEphemeralSecret()
}

func (w *Worker) handleGenerateEphemeralSecret(height int64, epoch beacon.EpochTime) {
	if w.kmStatus == nil || w.rtStatus == nil {
		return
	}
	if w.genEphSecInProgress || w.genEphSecRetry > generateSecretMaxRetries {
		return
	}
	if w.genSecHeight > height {
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
	generateEphemeralSecret := func(kmStatus *api.Status, rtStatus *runtimeStatus) {
		if err := w.generateEphemeralSecret(w.runtimeID, nextEpoch, kmStatus, rtStatus); err != nil {
			w.logger.Error("failed to generate ephemeral secret",
				"err", err,
				"retry", retry,
			)
			w.genEphSecDoneCh <- false
			return
		}

		w.setLastGeneratedEphemeralSecretEpoch(nextEpoch)
		w.genEphSecDoneCh <- true
	}

	go generateEphemeralSecret(w.kmStatus, w.rtStatus)
}

func (w *Worker) handleGenerateEphemeralSecretDone(ok bool) {
	// Unlock.
	w.genEphSecInProgress = false

	// Disarm ephemeral secret generation if we are still in the same epoch.
	if ok && w.genEphSecRetry > 0 {
		w.genEphSecRetry = math.MaxInt64
	}
}

func (w *Worker) handleLoadEphemeralSecret() {
	if w.kmStatus == nil || w.rtStatus == nil {
		return
	}

	var failed []*api.SignedEncryptedEphemeralSecret
	for _, secret := range w.ephSecrets {
		if err := w.loadEphemeralSecret(secret); err != nil {
			w.logger.Error("failed to load ephemeral secret",
				"err", err,
				"retry", w.loadEphSecRetry,
			)
			failed = append(failed, secret)
			continue
		}
		w.setLastLoadedEphemeralSecretEpoch(secret.Secret.Epoch)
	}
	w.ephSecrets = failed

	w.loadEphSecRetry++
	if w.loadEphSecRetry > loadSecretMaxRetries {
		// Disarm ephemeral secret loading.
		w.ephSecrets = nil
	}
}

func (w *Worker) handleStop() {
	w.logger.Info("termination requested")

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
}

func (w *Worker) worker() {
	w.logger.Info("starting key manager worker")

	defer close(w.quitCh)

	// Wait for consensus sync.
	w.logger.Info("delaying key manager worker start until after consensus synchronization")
	select {
	case <-w.stopCh:
		return
	case <-w.commonWorker.Consensus.Synced():
	}
	w.logger.Info("consensus has finished initial synchronization")

	// Provision the hosted runtime.
	w.logger.Info("provisioning key manager runtime")

	hrt, hrtNotifier, err := w.ProvisionHostedRuntime(w.ctx)
	if err != nil {
		w.logger.Error("failed to provision key manager runtime",
			"err", err,
		)
		return
	}

	hrtEventCh, hrtSub, err := hrt.WatchEvents(w.ctx)
	if err != nil {
		w.logger.Error("failed to subscribe to key manager runtime events",
			"err", err,
		)
		return
	}
	defer hrtSub.Close()

	if err = hrt.Start(); err != nil {
		w.logger.Error("failed to start key manager runtime",
			"err", err,
		)
		return
	}
	defer hrt.Stop()

	if err = hrtNotifier.Start(); err != nil {
		w.logger.Error("failed to start key manager runtime notifier",
			"err", err,
		)
		return
	}
	defer hrtNotifier.Stop()

	// Key managers always need to use the enclave version given to them in the bundle
	// as they need to make sure that replication is possible during upgrades.
	activeVersion := w.runtime.HostVersions()[0] // Init made sure we have exactly one.
	if err = w.SetHostedRuntimeVersion(w.ctx, activeVersion, nil); err != nil {
		w.logger.Error("failed to activate key manager runtime version",
			"err", err,
			"version", activeVersion,
		)
		return
	}

	// Need to explicitly watch for updates related to the key manager runtime
	// itself.
	knw := newKmNodeWatcher(w)
	go knw.watchNodes()

	// Subscribe to key manager status updates.
	statusCh, statusSub := w.backend.WatchStatuses()
	defer statusSub.Close()

	// Subscribe to key manager master secret publications.
	mstCh, mstSub := w.backend.WatchMasterSecrets()
	defer mstSub.Close()

	// Subscribe to key manager ephemeral secret publications.
	ephCh, ephSub := w.backend.WatchEphemeralSecrets()
	defer ephSub.Close()

	// Subscribe to epoch transitions in order to know when we need to refresh
	// the access control policy and choose a random block height for ephemeral
	// secret generation.
	epoch, err := w.commonWorker.Consensus.Beacon().GetEpoch(w.ctx, consensus.HeightLatest)
	if err != nil {
		w.logger.Error("failed to fetch current epoch",
			"err", err,
		)
		return
	}
	epoCh, epoSub, err := w.commonWorker.Consensus.Beacon().WatchLatestEpoch(w.ctx)
	if err != nil {
		w.logger.Error("failed to watch epochs",
			"err", err,
		)
		return
	}
	defer epoSub.Close()

	// Watch block heights so we can impose a random ephemeral secret
	// generation delay.
	blkCh, blkSub, err := w.commonWorker.Consensus.WatchBlocks(w.ctx)
	if err != nil {
		w.logger.Error("failed to watch blocks",
			"err", err,
		)
		return
	}
	defer blkSub.Close()

	// Subscribe to runtime registrations in order to know which runtimes
	// are using us as a key manager.
	rtCh, rtSub, err := w.commonWorker.Consensus.Registry().WatchRuntimes(w.ctx)
	if err != nil {
		w.logger.Error("failed to watch runtimes",
			"err", err,
		)
		return
	}
	defer rtSub.Close()

	for {
		select {
		case ev := <-hrtEventCh:
			w.handleRuntimeHostEvent(ev)
		case kmStatus := <-statusCh:
			w.handleStatusUpdate(kmStatus)
		case <-w.initEnclaveRetryCh:
			w.handleInitEnclave()
		case rsp := <-w.initEnclaveDoneCh:
			w.handleInitEnclaveDone(rsp)
		case rt := <-rtCh:
			w.handleRuntimeRegistrationEvent(rt)
		case epoch = <-epoCh:
			w.handleNewEpoch(epoch)
		case blk := <-blkCh:
			w.handleNewBlock(blk, epoch)
		case secret := <-mstCh:
			w.handleNewMasterSecret(secret)
		case ok := <-w.genMstSecDoneCh:
			w.handleGenerateMasterSecretDone(ok)
		case secret := <-ephCh:
			w.handleNewEphemeralSecret(secret, epoch)
		case ok := <-w.genEphSecDoneCh:
			w.handleGenerateEphemeralSecretDone(ok)
		case <-w.stopCh:
			w.handleStop()
			return
		}
	}
}

type clientRuntimeWatcher struct {
	w         *Worker
	runtimeID common.Namespace
	nodes     nodes.VersionedNodeDescriptorWatcher
}

func (crw *clientRuntimeWatcher) worker() {
	ch, sub, err := crw.nodes.WatchNodeUpdates()
	if err != nil {
		crw.w.logger.Error("failed to subscribe to client runtime node updates",
			"err", err,
			"runtime_id", crw.runtimeID,
		)
		return
	}
	defer sub.Close()

	for {
		select {
		case <-crw.w.ctx.Done():
			return
		case nu := <-ch:
			if nu.Reset {
				// Ignore reset events to avoid clearing the access list before setting a new one.
				// This is safe because a reset event is always followed by a freeze event after the
				// nodes have been set (even if the new set is empty).
				continue
			}
			crw.w.setAccessList(crw.runtimeID, crw.nodes.GetNodes())
		}
	}
}

func (crw *clientRuntimeWatcher) epochTransition() {
	crw.nodes.Reset()

	cms, err := crw.w.commonWorker.Consensus.Scheduler().GetCommittees(crw.w.ctx, &scheduler.GetCommitteesRequest{
		Height:    consensus.HeightLatest,
		RuntimeID: crw.runtimeID,
	})
	if err != nil {
		crw.w.logger.Error("failed to fetch client runtime committee",
			"err", err,
			"runtime_id", crw.runtimeID,
		)
		return
	}

	for _, cm := range cms {
		if cm.Kind != scheduler.KindComputeExecutor {
			continue
		}

		for _, member := range cm.Members {
			_, _ = crw.nodes.WatchNode(crw.w.ctx, member.PublicKey)
		}
	}

	crw.nodes.Freeze(0)

	crw.w.setAccessList(crw.runtimeID, crw.nodes.GetNodes())
}
