package oasis

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	commonGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci"
	tendermintCommon "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	tendermintFull "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/full"
	tendermintSeed "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/seed"
	"github.com/oasisprotocol/oasis-core/go/ias"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/pprof"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/byzantine"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
	workerConsensusRPC "github.com/oasisprotocol/oasis-core/go/worker/consensusrpc"
	"github.com/oasisprotocol/oasis-core/go/worker/keymanager"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	workerSentry "github.com/oasisprotocol/oasis-core/go/worker/sentry"
	workerGrpcSentry "github.com/oasisprotocol/oasis-core/go/worker/sentry/grpc"
	workerStorage "github.com/oasisprotocol/oasis-core/go/worker/storage"
)

// EnvNoSandbox is the env var to be set to 1 to force-disable sandboxing
// runtimes.
const EnvNoSandbox = "OASIS_UNSAFE_TESTS_NO_SANDBOX"

func isNoSandbox() bool {
	return os.Getenv(EnvNoSandbox) == "1"
}

const generatedConfigFilename = "config.yml"

// Argument is a single argument on the commandline, including its values.
type Argument struct {
	// Name is the name of the argument, i.e. the leading dashed component.
	Name string `json:"name"`
	// Values is the array of values passed to this argument.
	Values []string `json:"values"`
	// MultiValued tells the system that multiple occurrences of the same argument
	// should have their value arrays merged.
	MultiValued bool `json:"multi_valued"`
}

type argBuilder struct {
	vec []Argument

	// dontBlameOasis is true, if CfgDebugDontBlameOasis is passed.
	dontBlameOasis bool

	// config contains options that must be defined using a config file.
	config *viper.Viper
}

func (args *argBuilder) clone() *argBuilder {
	vec := make([]Argument, len(args.vec))
	copy(vec[:], args.vec)

	return &argBuilder{
		vec:            vec,
		dontBlameOasis: args.dontBlameOasis,
		config:         args.config,
	}
}

func (args *argBuilder) extraArgs(extra []Argument) *argBuilder {
	args.vec = append(args.vec, extra...)
	return args
}

func (args *argBuilder) mergeConfigMap(cfg map[string]interface{}) *argBuilder {
	if args.config == nil {
		args.config = viper.New()
	}
	if err := args.config.MergeConfigMap(cfg); err != nil {
		panic(fmt.Errorf("failed to merge config map: %w", err))
	}
	return args
}

func (args *argBuilder) internalSocketAddress(path string) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   grpc.CfgAddress,
		Values: []string{"unix:" + path},
	})
	return args
}

func (args *argBuilder) debugDontBlameOasis() *argBuilder {
	if !args.dontBlameOasis {
		args.vec = append(args.vec, Argument{
			Name: flags.CfgDebugDontBlameOasis,
		})
		args.dontBlameOasis = true
	}
	return args
}

func (args *argBuilder) debugAllowRoot() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name: flags.CfgDebugAllowRoot,
	})
	return args
}

func (args *argBuilder) debugAllowTestKeys() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name: cmdCommon.CfgDebugAllowTestKeys,
	})
	return args
}

func (args *argBuilder) debugAllowDebugEnclaves() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name: cmdCommon.CfgDebugAllowDebugEnclaves,
	})
	return args
}

func (args *argBuilder) debugSetRlimit() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   cmdCommon.CfgDebugRlimit,
		Values: []string{strconv.Itoa(int(cmdCommon.RequiredRlimit))},
	})
	return args
}

func (args *argBuilder) debugEnableProfiling(port uint16) *argBuilder {
	if port == 0 {
		return args
	}
	args.vec = append(args.vec, Argument{
		Name:   pprof.CfgPprofBind,
		Values: []string{"0.0.0.0:" + strconv.Itoa(int(port))},
	})
	return args
}

func (args *argBuilder) grpcServerPort(port uint16) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   grpc.CfgServerPort,
		Values: []string{strconv.Itoa(int(port))},
	})
	return args
}

func (args *argBuilder) grpcWait() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name: grpc.CfgWait,
	})
	return args
}

func (args *argBuilder) grpcLogDebug() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name: commonGrpc.CfgLogDebug,
	})
	return args
}

func (args *argBuilder) grpcDebugGrpcInternalSocketPath(path string) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   grpc.CfgDebugGrpcInternalSocketPath,
		Values: []string{path},
	})
	return args
}

func (args *argBuilder) consensusValidator() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name: flags.CfgConsensusValidator,
	})
	return args
}

func (args *argBuilder) tendermintMinGasPrice(price uint64) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   tendermintFull.CfgMinGasPrice,
		Values: []string{strconv.Itoa(int(price))},
	})
	return args
}

func (args *argBuilder) tendermintSubmissionGasPrice(price uint64) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   tendermintCommon.CfgSubmissionGasPrice,
		Values: []string{strconv.Itoa(int(price))},
	})
	return args
}

func (args *argBuilder) tendermintPrune(numKept uint64, interval time.Duration) *argBuilder {
	if numKept > 0 {
		args.vec = append(args.vec, []Argument{
			{tendermintFull.CfgABCIPruneStrategy, []string{abci.PruneKeepN.String()}, false},
			{tendermintFull.CfgABCIPruneNumKept, []string{strconv.FormatUint(numKept, 10)}, false},
			{tendermintFull.CfgABCIPruneInterval, []string{interval.String()}, false},
		}...)
	} else {
		args.vec = append(args.vec, Argument{
			Name:   tendermintFull.CfgABCIPruneStrategy,
			Values: []string{abci.PruneNone.String()},
		})
	}
	return args
}

func (args *argBuilder) tendermintRecoverCorruptedWAL(enable bool) *argBuilder {
	if enable {
		args.vec = append(args.vec, Argument{Name: tendermintFull.CfgDebugUnsafeReplayRecoverCorruptedWAL})
	}
	return args
}

func (args *argBuilder) tendermintCoreAddress(port uint16) *argBuilder {
	args.vec = append(args.vec, []Argument{
		{tendermintCommon.CfgCoreListenAddress, []string{"tcp://0.0.0.0:" + strconv.Itoa(int(port))}, false},
		{tendermintCommon.CfgCoreExternalAddress, []string{"tcp://127.0.0.1:" + strconv.Itoa(int(port))}, false},
	}...)
	return args
}

func (args *argBuilder) tendermintSentryUpstreamAddress(addrs []string) *argBuilder {
	for _, addr := range addrs {
		args.vec = append(args.vec, Argument{
			Name:        tendermintFull.CfgSentryUpstreamAddress,
			Values:      []string{addr},
			MultiValued: true,
		})
	}
	return args
}

func (args *argBuilder) tendermintDisablePeerExchange() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name: tendermintFull.CfgP2PDisablePeerExchange,
	})
	return args
}

func (args *argBuilder) tendermintSeedMode() *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   tendermint.CfgMode,
		Values: []string{consensusAPI.ModeSeed.String()},
	})
	return args
}

func (args *argBuilder) tendermintSeedDisableAddrBookFromGenesis() *argBuilder {
	args.vec = append(args.vec, Argument{Name: tendermintSeed.CfgDebugDisableAddrBookFromGenesis})
	return args
}

func (args *argBuilder) tendermintDebugAddrBookLenient() *argBuilder {
	args.vec = append(args.vec, Argument{Name: tendermintCommon.CfgDebugP2PAddrBookLenient})
	return args
}

func (args *argBuilder) tendermintDebugAllowDuplicateIP() *argBuilder {
	args.vec = append(args.vec, Argument{Name: tendermintCommon.CfgDebugP2PAllowDuplicateIP})
	return args
}

func (args *argBuilder) tendermintStateSync(
	consensusNodes []string,
	trustHeight uint64,
	trustHash string,
) *argBuilder {
	args.vec = append(args.vec, []Argument{
		{tendermintFull.CfgConsensusStateSyncEnabled, nil, false},
		{tendermintFull.CfgConsensusStateSyncTrustHeight, []string{strconv.FormatUint(trustHeight, 10)}, false},
		{tendermintFull.CfgConsensusStateSyncTrustHash, []string{trustHash}, false},
	}...)
	for _, address := range consensusNodes {
		args.vec = append(args.vec, Argument{tendermintFull.CfgConsensusStateSyncConsensusNode, []string{address}, true})
	}
	return args
}

func (args *argBuilder) tendermintUpgradeStopDelay(delay time.Duration) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   tendermintFull.CfgUpgradeStopDelay,
		Values: []string{delay.String()},
	})
	return args
}

func (args *argBuilder) storageBackend(backend string) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   workerStorage.CfgBackend,
		Values: []string{backend},
	})
	return args
}

func (args *argBuilder) tendermintSupplementarySanity(interval uint64) *argBuilder {
	if interval > 0 {
		args.vec = append(args.vec, Argument{Name: tendermintFull.CfgSupplementarySanityEnabled})
		args.vec = append(args.vec, Argument{
			Name:   tendermintFull.CfgSupplementarySanityInterval,
			Values: []string{strconv.Itoa(int(interval))},
		})
	}
	return args
}

func (args *argBuilder) workerClientPort(port uint16) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   workerCommon.CfgClientPort,
		Values: []string{strconv.Itoa(int(port))},
	})
	return args
}

func (args *argBuilder) workerCommonSentryAddresses(addrs []string) *argBuilder {
	for _, addr := range addrs {
		args.vec = append(args.vec, Argument{
			Name:        workerCommon.CfgSentryAddresses,
			Values:      []string{addr},
			MultiValued: true,
		})
	}
	return args
}

func (args *argBuilder) workerSentryGrpcClientAddress(addrs []string) *argBuilder {
	for _, addr := range addrs {
		args.vec = append(args.vec, Argument{
			Name:        workerGrpcSentry.CfgClientAddresses,
			Values:      []string{addr},
			MultiValued: true,
		})
	}
	return args
}

func (args *argBuilder) workerSentryGrpcClientPort(port uint16) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   workerGrpcSentry.CfgClientPort,
		Values: []string{strconv.Itoa(int(port))},
	})
	return args
}

func (args *argBuilder) workerP2pPort(port uint16) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   p2p.CfgP2pPort,
		Values: []string{strconv.Itoa(int(port))},
	})
	return args
}

func (args *argBuilder) runtimeMode(mode runtimeRegistry.RuntimeMode) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   runtimeRegistry.CfgRuntimeMode,
		Values: []string{string(mode)},
	})
	return args
}

func (args *argBuilder) runtimeProvisioner(provisioner string) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   runtimeRegistry.CfgRuntimeProvisioner,
		Values: []string{provisioner},
	})
	return args
}

func (args *argBuilder) runtimeSGXLoader(fn string) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   runtimeRegistry.CfgRuntimeSGXLoader,
		Values: []string{fn},
	})
	return args
}

func (args *argBuilder) runtimePath(rt *Runtime) *argBuilder {
	for _, path := range rt.BundlePaths() {
		args.vec = append(args.vec, Argument{
			Name:        runtimeRegistry.CfgRuntimePaths,
			Values:      []string{path},
			MultiValued: true,
		})
	}
	return args
}

func (args *argBuilder) workerKeymanagerRuntimeID(id common.Namespace) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   keymanager.CfgRuntimeID,
		Values: []string{id.String()},
	})
	return args
}

func (args *argBuilder) workerKeymanagerMayGenerate() *argBuilder {
	args.vec = append(args.vec, Argument{Name: keymanager.CfgMayGenerate})
	return args
}

func (args *argBuilder) workerKeymanagerPrivatePeerPubKeys(peerPKs []string) *argBuilder {
	for _, pk := range peerPKs {
		args.vec = append(args.vec, Argument{
			Name:        keymanager.CfgPrivatePeerPubKeys,
			Values:      []string{pk},
			MultiValued: true,
		})
	}
	return args
}

func (args *argBuilder) workerSentryEnabled() *argBuilder {
	args.vec = append(args.vec, Argument{Name: workerSentry.CfgEnabled})
	return args
}

func (args *argBuilder) workerGrpcSentryEnabled() *argBuilder {
	args.vec = append(args.vec, Argument{Name: workerGrpcSentry.CfgEnabled})
	return args
}

func (args *argBuilder) grpcSentryUpstreamAddresses(addrs []string) *argBuilder {
	for _, addr := range addrs {
		args.vec = append(args.vec, Argument{
			Name:        workerGrpcSentry.CfgUpstreamAddress,
			Values:      []string{addr},
			MultiValued: true,
		})
	}
	return args
}

func (args *argBuilder) grpcSentryUpstreamIDs(ids []string) *argBuilder {
	for _, id := range ids {
		args.vec = append(args.vec, Argument{
			Name:        workerGrpcSentry.CfgUpstreamID,
			Values:      []string{id},
			MultiValued: true,
		})
	}
	return args
}

func (args *argBuilder) workerSentryControlPort(port uint16) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   workerSentry.CfgControlPort,
		Values: []string{strconv.Itoa(int(port))},
	})
	return args
}

func (args *argBuilder) workerSentryUpstreamTLSKeys(keys []string) *argBuilder {
	for _, key := range keys {
		args.vec = append(args.vec, Argument{
			Name:        workerSentry.CfgAuthorizedControlPubkeys,
			Values:      []string{key},
			MultiValued: true,
		})
	}
	return args
}

func (args *argBuilder) workerStoragePublicRPCEnabled(enabled bool) *argBuilder {
	if enabled {
		args.vec = append(args.vec, Argument{Name: workerStorage.CfgWorkerPublicRPCEnabled})
	}
	return args
}

func (args *argBuilder) workerStorageDebugDisableCheckpointSync(disable bool) *argBuilder {
	if disable {
		args.vec = append(args.vec, Argument{Name: workerStorage.CfgWorkerCheckpointSyncDisabled})
	}
	return args
}

func (args *argBuilder) workerStorageCheckpointerEnabled(enable bool) *argBuilder {
	if enable {
		args.vec = append(args.vec, Argument{Name: workerStorage.CfgWorkerCheckpointerEnabled})
	}
	return args
}

func (args *argBuilder) workerStorageCheckpointCheckInterval(interval time.Duration) *argBuilder {
	if interval > 0 {
		args.vec = append(args.vec, Argument{
			Name:   workerStorage.CfgWorkerCheckpointCheckInterval,
			Values: []string{interval.String()},
		})
	}
	return args
}

func (args *argBuilder) workerCertificateRotation(enabled bool) *argBuilder {
	arg := Argument{Name: registration.CfgRegistrationRotateCerts}
	switch enabled {
	case false:
		arg.Values = []string{"0"}
	case true:
		arg.Values = []string{"1"}
	}
	args.vec = append(args.vec, arg)
	return args
}

func (args *argBuilder) workerConsensusRPCEnabled() *argBuilder {
	args.vec = append(args.vec, Argument{Name: workerConsensusRPC.CfgWorkerEnabled})
	return args
}

func (args *argBuilder) iasDebugMock() *argBuilder {
	args.vec = append(args.vec, Argument{Name: "ias.debug.mock"})
	return args
}

func (args *argBuilder) iasSPID(spid []byte) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   "ias.spid",
		Values: []string{hex.EncodeToString(spid)},
	})
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

func (args *argBuilder) addSentryComputeWorkers(computeWorkers []*Compute) *argBuilder {
	var addrs, ids, tmAddrs, sentryPubKeys []string
	for _, computeWorker := range computeWorkers {
		addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", computeWorker.clientPort))
		ids = append(ids, computeWorker.NodeID.String())
		tmAddrs = append(tmAddrs, fmt.Sprintf("%s@127.0.0.1:%d", computeWorker.tmAddress, computeWorker.consensusPort))
		key, _ := computeWorker.sentryPubKey.MarshalText()
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
		args.vec = append(args.vec, Argument{
			Name:        tendermintCommon.CfgP2PSeed,
			Values:      []string{fmt.Sprintf("%s@127.0.0.1:%d", seed.tmAddress, seed.consensusPort)},
			MultiValued: true,
		})
	}
	return args
}

func (args *argBuilder) configureDebugCrashPoints(prob float64) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   crash.CfgDefaultCrashPointProbability,
		Values: []string{fmt.Sprintf("%f", prob)},
	})
	return args
}

func (args *argBuilder) appendNodeMetrics(node *Node) *argBuilder {
	args.vec = append(args.vec, []Argument{
		{metrics.CfgMetricsMode, []string{metrics.MetricsModePush}, false},
		{metrics.CfgMetricsAddr, []string{viper.GetString(metrics.CfgMetricsAddr)}, false},
		{metrics.CfgMetricsInterval, []string{viper.GetString(metrics.CfgMetricsInterval)}, false},
		{metrics.CfgMetricsJobName, []string{node.Name}, false},
	}...)

	// Append labels.
	ti := node.net.env.ScenarioInfo()
	labels := metrics.GetDefaultPushLabels(ti)
	var l []string
	for k, v := range labels {
		l = append(l, k+"="+v)
	}
	args.vec = append(args.vec, Argument{
		Name:   metrics.CfgMetricsLabels,
		Values: []string{strings.Join(l, ",")},
	})

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

	args.vec = append(args.vec, []Argument{
		{runtimeRegistry.CfgHistoryPrunerStrategy, []string{p.Strategy}, false},
		{runtimeRegistry.CfgHistoryPrunerInterval, []string{p.Interval.String()}, false},
		{runtimeRegistry.CfgHistoryPrunerKeepLastNum, []string{strconv.Itoa(int(p.NumKept))}, false},
	}...)
	return args
}

func (args *argBuilder) appendHostedRuntime(rt *Runtime, localConfig map[string]interface{}) *argBuilder {
	args = args.runtimePath(rt).
		appendRuntimePruner(&rt.pruner)

	// When local runtime config is set, we need to generate a config file.
	if localConfig != nil {
		args.mergeConfigMap(map[string]interface{}{
			"runtime": map[string]interface{}{
				"config": map[string]interface{}{
					rt.ID().String(): localConfig,
				},
			},
		})
	}

	return args
}

func (args *argBuilder) appendEntity(ent *Entity) *argBuilder {
	if ent.dir != nil {
		dir := ent.dir.String()
		args.vec = append(args.vec, Argument{
			Name:   registration.CfgRegistrationEntity,
			Values: []string{filepath.Join(dir, "entity.json")},
		})
	} else if ent.isDebugTestEntity {
		args.vec = append(args.vec, Argument{Name: flags.CfgDebugTestEntity})
	}
	return args
}

func (args *argBuilder) appendIASProxy(iasProxy *iasProxy) *argBuilder {
	if iasProxy != nil {
		args.vec = append(args.vec, []Argument{
			{ias.CfgProxyAddress, []string{fmt.Sprintf("%s@127.0.0.1:%d", iasProxy.tlsPublicKey, iasProxy.grpcPort)}, false},
		}...)
		if iasProxy.mock {
			args.vec = append(args.vec, Argument{Name: ias.CfgDebugSkipVerify})
		}
	}
	return args
}

func (args *argBuilder) byzantineFakeSGX() *argBuilder {
	args.vec = append(args.vec, Argument{Name: byzantine.CfgFakeSGX})
	return args
}

func (args *argBuilder) byzantineVersionFakeEnclaveID(rt *Runtime) *argBuilder {
	eid := rt.GetEnclaveIdentity(0)
	args.vec = append(args.vec, Argument{
		Name:   byzantine.CfgVersionFakeEnclaveID,
		Values: []string{eid.String()},
	})
	return args
}

func (args *argBuilder) byzantineActivationEpoch(epoch beacon.EpochTime) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   byzantine.CfgActivationEpoch,
		Values: []string{strconv.FormatUint(uint64(epoch), 10)},
	})
	return args
}

func (args *argBuilder) byzantineRuntimeID(runtimeID common.Namespace) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   byzantine.CfgRuntimeID,
		Values: []string{runtimeID.String()},
	})
	return args
}

func (args *argBuilder) configFile(path string) *argBuilder {
	args.vec = append(args.vec, Argument{
		Name:   cmdCommon.CfgConfigFile,
		Values: []string{path},
	})
	return args
}

func (args *argBuilder) merge(configDir string) []string {
	output := []string{}
	shipped := map[string][]string{}
	multiValued := map[string][][]string{}

	slicesEqual := func(s1, s2 []string) bool {
		if len(s1) != len(s2) {
			return false
		}
		for i := range s1 {
			if s1[i] != s2[i] {
				return false
			}
		}
		return true
	}

	// Generate a configuration file in the passed directory when required.
	if args.config != nil {
		configFile := filepath.Join(configDir, generatedConfigFilename)
		if err := args.config.WriteConfigAs(configFile); err != nil {
			panic(fmt.Errorf("args: failed to write config file to %s: %w", configDir, err))
		}
		args.configFile(configFile)
	}

	for _, arg := range args.vec {
		if arg.MultiValued {
			ok := true
			for _, el := range multiValued[arg.Name] {
				if slicesEqual(el, arg.Values) {
					ok = false
					break
				}
			}
			if ok {
				output = append(output, "--"+arg.Name)
				output = append(output, arg.Values...)
				multiValued[arg.Name] = append(multiValued[arg.Name], arg.Values)
			}
		} else {
			vals, ok := shipped[arg.Name]
			if !ok {
				output = append(output, "--"+arg.Name)
				output = append(output, arg.Values...)
				shipped[arg.Name] = arg.Values
			} else {
				if !slicesEqual(vals, arg.Values) {
					panic(fmt.Sprintf("args: single-valued argument given multiple times with different values (%s)", arg.Name))
				}
			}
		}
	}
	return output
}

func newArgBuilder() *argBuilder {
	return &argBuilder{}
}
