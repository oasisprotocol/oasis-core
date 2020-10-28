package oasis

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	commonGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci"
	tendermintCommon "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	tendermintFull "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/full"
	tendermintSeed "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/seed"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	"github.com/oasisprotocol/oasis-core/go/ias"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/byzantine"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
	"github.com/oasisprotocol/oasis-core/go/worker/compute"
	"github.com/oasisprotocol/oasis-core/go/worker/compute/executor"
	workerConsensusRPC "github.com/oasisprotocol/oasis-core/go/worker/consensusrpc"
	"github.com/oasisprotocol/oasis-core/go/worker/keymanager"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	workerSentry "github.com/oasisprotocol/oasis-core/go/worker/sentry"
	workerGrpcSentry "github.com/oasisprotocol/oasis-core/go/worker/sentry/grpc"
	workerStorage "github.com/oasisprotocol/oasis-core/go/worker/storage"
)

type argBuilder struct {
	vec []string

	// dontBlameOasis is true, if CfgDebugDontBlameOasis is passed.
	dontBlameOasis bool
}

func (args *argBuilder) internalSocketAddress(path string) *argBuilder {
	args.vec = append(args.vec, "--"+grpc.CfgAddress, "unix:"+path)
	return args
}

func (args *argBuilder) debugDontBlameOasis() *argBuilder {
	if !args.dontBlameOasis {
		args.vec = append(args.vec, "--"+flags.CfgDebugDontBlameOasis)
		args.dontBlameOasis = true
	}
	return args
}

func (args *argBuilder) debugAllowTestKeys() *argBuilder {
	args.vec = append(args.vec, "--"+cmdCommon.CfgDebugAllowTestKeys)
	return args
}

func (args *argBuilder) grpcServerPort(port uint16) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + grpc.CfgServerPort, strconv.Itoa(int(port)),
	}...)
	return args
}

func (args *argBuilder) grpcWait() *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + grpc.CfgWait,
	}...)
	return args
}

func (args *argBuilder) grpcLogDebug() *argBuilder {
	args.vec = append(args.vec, "--"+commonGrpc.CfgLogDebug)
	return args
}

func (args *argBuilder) grpcDebugGrpcInternalSocketPath(path string) *argBuilder {
	args.vec = append(args.vec, "--"+grpc.CfgDebugGrpcInternalSocketPath, path)
	return args
}

func (args *argBuilder) consensusValidator() *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + flags.CfgConsensusValidator,
	}...)
	return args
}

func (args *argBuilder) tendermintMinGasPrice(price uint64) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + tendermintFull.CfgMinGasPrice, strconv.Itoa(int(price)),
	}...)
	return args
}

func (args *argBuilder) tendermintSubmissionGasPrice(price uint64) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + tendermintCommon.CfgSubmissionGasPrice, strconv.Itoa(int(price)),
	}...)
	return args
}

func (args *argBuilder) tendermintPrune(numKept uint64) *argBuilder {
	if numKept > 0 {
		args.vec = append(args.vec,
			"--"+tendermintFull.CfgABCIPruneStrategy, abci.PruneKeepN.String(),
			"--"+tendermintFull.CfgABCIPruneNumKept, strconv.FormatUint(numKept, 10),
		)
	} else {
		args.vec = append(args.vec,
			"--"+tendermintFull.CfgABCIPruneStrategy, abci.PruneNone.String(),
		)
	}
	return args
}

func (args *argBuilder) tendermintDebugDisableCheckTx(disable bool) *argBuilder {
	if disable {
		args.vec = append(args.vec, "--"+tendermintFull.CfgDebugDisableCheckTx)
	}
	return args
}

func (args *argBuilder) tendermintRecoverCorruptedWAL(enable bool) *argBuilder {
	if enable {
		args.vec = append(args.vec, "--"+tendermintFull.CfgDebugUnsafeReplayRecoverCorruptedWAL)
	}
	return args
}

func (args *argBuilder) tendermintCoreAddress(port uint16) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + tendermintCommon.CfgCoreListenAddress, "tcp://0.0.0.0:" + strconv.Itoa(int(port)),
		"--" + tendermintCommon.CfgCoreExternalAddress, "tcp://127.0.0.1:" + strconv.Itoa(int(port)),
	}...)
	return args
}

func (args *argBuilder) tendermintSentryUpstreamAddress(addrs []string) *argBuilder {
	for _, addr := range addrs {
		args.vec = append(args.vec, []string{
			"--" + tendermintFull.CfgSentryUpstreamAddress, addr,
		}...)
	}
	return args
}

func (args *argBuilder) tendermintDisablePeerExchange() *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + tendermintFull.CfgP2PDisablePeerExchange,
	}...)
	return args
}

func (args *argBuilder) tendermintSeedMode() *argBuilder {
	args.vec = append(args.vec, "--"+tendermint.CfgMode, tendermint.ModeSeed)
	return args
}

func (args *argBuilder) tendermintSeedDisableAddrBookFromGenesis() *argBuilder {
	args.vec = append(args.vec, "--"+tendermintSeed.CfgDebugDisableAddrBookFromGenesis)
	return args
}

func (args *argBuilder) tendermintDebugAddrBookLenient() *argBuilder {
	args.vec = append(args.vec, "--"+tendermintCommon.CfgDebugP2PAddrBookLenient)
	return args
}

func (args *argBuilder) tendermintDebugAllowDuplicateIP() *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + tendermintCommon.CfgDebugP2PAllowDuplicateIP,
	}...)
	return args
}

func (args *argBuilder) tendermintStateSync(
	consensusNodes []string,
	trustHeight uint64,
	trustHash string,
) *argBuilder {
	args.vec = append(args.vec,
		"--"+tendermintFull.CfgConsensusStateSyncEnabled,
		"--"+tendermintFull.CfgConsensusStateSyncTrustHeight, strconv.FormatUint(trustHeight, 10),
		"--"+tendermintFull.CfgConsensusStateSyncTrustHash, trustHash,
	)
	for _, address := range consensusNodes {
		args.vec = append(args.vec, "--"+tendermintFull.CfgConsensusStateSyncConsensusNode, address)
	}
	return args
}

func (args *argBuilder) storageBackend(backend string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerStorage.CfgBackend, backend,
	}...)
	return args
}

func (args *argBuilder) runtimeSupported(id common.Namespace) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + runtimeRegistry.CfgSupported, id.String(),
	}...)
	return args
}

func (args *argBuilder) tendermintSupplementarySanityEnabled() *argBuilder {
	args.vec = append(args.vec, "--"+tendermintFull.CfgSupplementarySanityEnabled)
	args.vec = append(args.vec, []string{
		"--" + tendermintFull.CfgSupplementarySanityInterval, "1",
	}...)
	return args
}

func (args *argBuilder) runtimeTagIndexerBackend(backend string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + runtimeRegistry.CfgTagIndexerBackend, backend,
	}...)
	return args
}

func (args *argBuilder) runtimeClientMaxTransactionAge(maxTxAge int64) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + runtimeClient.CfgMaxTransactionAge, strconv.Itoa(int(maxTxAge)),
	}...)
	return args
}

func (args *argBuilder) workerClientPort(port uint16) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerCommon.CfgClientPort, strconv.Itoa(int(port)),
	}...)
	return args
}

func (args *argBuilder) workerCommonSentryAddresses(addrs []string) *argBuilder {
	for _, addr := range addrs {
		args.vec = append(args.vec, []string{
			"--" + workerCommon.CfgSentryAddresses, addr,
		}...)
	}
	return args
}

func (args *argBuilder) workerSentryGrpcClientAddress(addrs []string) *argBuilder {
	for _, addr := range addrs {
		args.vec = append(args.vec, []string{
			"--" + workerGrpcSentry.CfgClientAddresses, addr,
		}...)
	}
	return args
}

func (args *argBuilder) workerSentryGrpcClientPort(port uint16) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerGrpcSentry.CfgClientPort, strconv.Itoa(int(port)),
	}...)
	return args
}

func (args *argBuilder) workerP2pPort(port uint16) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + p2p.CfgP2pPort, strconv.Itoa(int(port)),
	}...)
	return args
}

func (args *argBuilder) workerP2pEnabled() *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + p2p.CfgP2PEnabled,
	}...)
	return args
}

func (args *argBuilder) workerRuntimeProvisioner(provisioner string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerCommon.CfgRuntimeProvisioner, provisioner,
	}...)
	return args
}

func (args *argBuilder) workerRuntimeSGXLoader(fn string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerCommon.CfgRuntimeSGXLoader, fn,
	}...)
	return args
}

func (args *argBuilder) workerRuntimePath(id common.Namespace, fn string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerCommon.CfgRuntimePaths, id.String() + "=" + fn,
	}...)
	return args
}

func (args *argBuilder) workerComputeEnabled() *argBuilder {
	args.vec = append(args.vec, "--"+compute.CfgWorkerEnabled)
	return args
}

func (args *argBuilder) workerKeymanagerEnabled() *argBuilder {
	args.vec = append(args.vec, "--"+keymanager.CfgEnabled)
	return args
}

func (args *argBuilder) workerKeymanagerRuntimeID(id common.Namespace) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + keymanager.CfgRuntimeID, id.String(),
	}...)
	return args
}

func (args *argBuilder) workerKeymanagerMayGenerate() *argBuilder {
	args.vec = append(args.vec, "--"+keymanager.CfgMayGenerate)
	return args
}

func (args *argBuilder) workerSentryEnabled() *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerSentry.CfgEnabled,
	}...)
	return args
}

func (args *argBuilder) workerGrpcSentryEnabled() *argBuilder {
	args.vec = append(args.vec, "--"+workerGrpcSentry.CfgEnabled)
	return args
}

func (args *argBuilder) grpcSentryUpstreamAddresses(addrs []string) *argBuilder {
	for _, addr := range addrs {
		args.vec = append(args.vec, []string{
			"--" + workerGrpcSentry.CfgUpstreamAddress, addr,
		}...)
	}
	return args
}

func (args *argBuilder) grpcSentryUpstreamIDs(ids []string) *argBuilder {
	for _, id := range ids {
		args.vec = append(args.vec, []string{
			"--" + workerGrpcSentry.CfgUpstreamID, id,
		}...)
	}
	return args
}

func (args *argBuilder) workerSentryControlPort(port uint16) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerSentry.CfgControlPort, strconv.Itoa(int(port)),
	}...)
	return args
}

func (args *argBuilder) workerSentryUpstreamTLSKeys(keys []string) *argBuilder {
	for _, key := range keys {
		args.vec = append(args.vec, []string{
			"--" + workerSentry.CfgAuthorizedControlPubkeys, key,
		}...)
	}
	return args
}

func (args *argBuilder) workerStorageEnabled() *argBuilder {
	args.vec = append(args.vec, "--"+workerStorage.CfgWorkerEnabled)
	return args
}

func (args *argBuilder) workerStorageDebugIgnoreApplies(ignore bool) *argBuilder {
	if ignore {
		args.vec = append(args.vec, "--"+workerStorage.CfgWorkerDebugIgnoreApply)
	}
	return args
}

func (args *argBuilder) workerStorageDebugDisableCheckpointSync(disable bool) *argBuilder {
	if disable {
		args.vec = append(args.vec, "--"+workerStorage.CfgWorkerCheckpointSyncDisabled)
	}
	return args
}

func (args *argBuilder) workerStorageCheckpointCheckInterval(interval time.Duration) *argBuilder {
	if interval > 0 {
		args.vec = append(args.vec, "--"+workerStorage.CfgWorkerCheckpointCheckInterval, interval.String())
	}
	return args
}

func (args *argBuilder) workerCertificateRotation(enabled bool) *argBuilder {
	switch enabled {
	case false:
		args.vec = append(args.vec, []string{
			"--" + registration.CfgRegistrationRotateCerts, "0",
		}...)
	case true:
		args.vec = append(args.vec, []string{
			"--" + registration.CfgRegistrationRotateCerts, "1",
		}...)
	}
	return args
}

func (args *argBuilder) workerExecutorScheduleCheckTxEnabled() *argBuilder {
	args.vec = append(args.vec, "--"+executor.CfgScheduleCheckTxEnabled)
	return args
}

func (args *argBuilder) workerConsensusRPCEnabled() *argBuilder {
	args.vec = append(args.vec, "--"+workerConsensusRPC.CfgWorkerEnabled)
	return args
}

func (args *argBuilder) iasUseGenesis() *argBuilder {
	args.vec = append(args.vec, "--ias.use_genesis")
	return args
}

func (args *argBuilder) iasDebugMock() *argBuilder {
	args.vec = append(args.vec, "--ias.debug.mock")
	return args
}

func (args *argBuilder) iasSPID(spid []byte) *argBuilder {
	args.vec = append(args.vec, []string{
		"--ias.spid", hex.EncodeToString(spid),
	}...)
	return args
}

func (args *argBuilder) addSentries(sentries []*Sentry) *argBuilder {
	var addrs []string
	for _, sentry := range sentries {
		addrs = append(addrs, fmt.Sprintf("%s@127.0.0.1:%d", sentry.tlsPublicKey.String(), sentry.controlPort))
	}
	return args.workerCommonSentryAddresses(addrs)
}

func (args *argBuilder) addValidatorsAsSentryUpstreams(validators []*Validator) *argBuilder {
	var addrs, sentryPubKeys []string
	for _, val := range validators {
		addrs = append(addrs, fmt.Sprintf("%s@127.0.0.1:%d", val.tmAddress, val.consensusPort))
		key, _ := val.sentryPubKey.MarshalText()
		sentryPubKeys = append(sentryPubKeys, string(key))
	}
	return args.tendermintSentryUpstreamAddress(addrs).workerSentryUpstreamTLSKeys(sentryPubKeys)
}

func (args *argBuilder) addSentryStorageWorkers(storageWorkers []*Storage) *argBuilder {
	var addrs, ids, tmAddrs, sentryPubKeys []string
	for _, storageWorker := range storageWorkers {
		addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", storageWorker.clientPort))
		ids = append(ids, storageWorker.NodeID.String())
		tmAddrs = append(tmAddrs, fmt.Sprintf("%s@127.0.0.1:%d", storageWorker.tmAddress, storageWorker.consensusPort))
		key, _ := storageWorker.sentryPubKey.MarshalText()
		sentryPubKeys = append(sentryPubKeys, string(key))
	}
	return args.grpcSentryUpstreamAddresses(addrs).
		grpcSentryUpstreamIDs(ids).
		tendermintSentryUpstreamAddress(tmAddrs).
		workerSentryUpstreamTLSKeys(sentryPubKeys)
}

func (args *argBuilder) addSentryKeymanagerWorkers(keymanagerWorkers []*Keymanager) *argBuilder {
	var addrs, ids, tmAddrs, sentryPubKeys []string
	for _, keymanager := range keymanagerWorkers {
		addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", keymanager.workerClientPort))
		ids = append(ids, keymanager.NodeID.String())
		tmAddrs = append(tmAddrs, fmt.Sprintf("%s@127.0.0.1:%d", keymanager.tmAddress, keymanager.consensusPort))
		key, _ := keymanager.sentryPubKey.MarshalText()
		sentryPubKeys = append(sentryPubKeys, string(key))
	}
	return args.grpcSentryUpstreamAddresses(addrs).
		grpcSentryUpstreamIDs(ids).
		tendermintSentryUpstreamAddress(tmAddrs).
		workerSentryUpstreamTLSKeys(sentryPubKeys)
}

func (args *argBuilder) appendSeedNodes(seeds []*Seed) *argBuilder {
	for _, seed := range seeds {
		args.vec = append(args.vec, []string{
			"--" + tendermintCommon.CfgP2PSeed, fmt.Sprintf("%s@127.0.0.1:%d", seed.tmAddress, seed.consensusPort),
		}...)
	}
	return args
}

func (args *argBuilder) appendNodeMetrics(node *Node) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + metrics.CfgMetricsMode, metrics.MetricsModePush,
		"--" + metrics.CfgMetricsAddr, viper.GetString(metrics.CfgMetricsAddr),
		"--" + metrics.CfgMetricsInterval, viper.GetString(metrics.CfgMetricsInterval),
		"--" + metrics.CfgMetricsJobName, node.Name,
	}...)

	// Append labels.
	args.vec = append(args.vec, "--"+metrics.CfgMetricsLabels)
	ti := node.net.env.ScenarioInfo()
	labels := metrics.GetDefaultPushLabels(ti)
	var l []string
	for k, v := range labels {
		l = append(l, k+"="+v)
	}
	args.vec = append(args.vec, strings.Join(l, ","))

	return args
}

func (args *argBuilder) appendNetwork(net *Network) *argBuilder {
	args = args.grpcLogDebug()
	return args
}

func (args *argBuilder) appendRuntimePruner(p *RuntimePrunerCfg) *argBuilder {
	if p.Strategy == "" {
		return args
	}

	args.vec = append(args.vec, []string{
		"--" + runtimeRegistry.CfgHistoryPrunerStrategy, p.Strategy,
		"--" + runtimeRegistry.CfgHistoryPrunerInterval, p.Interval.String(),
		"--" + runtimeRegistry.CfgHistoryPrunerKeepLastNum, strconv.Itoa(int(p.NumKept)),
	}...)
	return args
}

func (args *argBuilder) appendComputeNodeRuntime(rt *Runtime, binaryIdx int) *argBuilder {
	args = args.runtimeSupported(rt.id).
		workerRuntimePath(rt.id, rt.binaries[binaryIdx]).
		appendRuntimePruner(&rt.pruner)
	return args
}

func (args *argBuilder) appendEntity(ent *Entity) *argBuilder {
	if ent.dir != nil {
		dir := ent.dir.String()
		args.vec = append(args.vec, []string{
			"--" + registration.CfgRegistrationEntity, filepath.Join(dir, "entity.json"),
		}...)
	} else if ent.isDebugTestEntity {
		args.vec = append(args.vec, "--"+flags.CfgDebugTestEntity)
	}
	return args
}

func (args *argBuilder) appendIASProxy(iasProxy *iasProxy) *argBuilder {
	if iasProxy != nil {
		args.vec = append(args.vec, []string{
			"--" + ias.CfgProxyAddress, "127.0.0.1:" + strconv.Itoa(int(iasProxy.grpcPort)),
			"--" + ias.CfgTLSCertFile, iasProxy.tlsCertPath(),
			"--" + ias.CfgAllowDebugEnclaves,
		}...)
		if iasProxy.mock {
			args.vec = append(args.vec, "--"+ias.CfgDebugSkipVerify)
		}
	}
	return args
}

func (args *argBuilder) byzantineFakeSGX() *argBuilder {
	args.vec = append(args.vec, "--"+byzantine.CfgFakeSGX)
	return args
}

func (args *argBuilder) byzantineVersionFakeEnclaveID(rt *Runtime) *argBuilder {
	eid := sgx.EnclaveIdentity{
		MrEnclave: *rt.mrEnclaves[0],
		MrSigner:  *rt.mrSigner,
	}
	args.vec = append(args.vec, "--"+byzantine.CfgVersionFakeEnclaveID, eid.String())
	return args
}

func (args *argBuilder) byzantineActivationEpoch(epoch epochtime.EpochTime) *argBuilder {
	args.vec = append(args.vec, "--"+byzantine.CfgActivationEpoch, strconv.FormatUint(uint64(epoch), 10))
	return args
}

func newArgBuilder() *argBuilder {
	return &argBuilder{}
}
