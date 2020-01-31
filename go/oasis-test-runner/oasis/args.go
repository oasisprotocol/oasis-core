package oasis

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/oasislabs/oasis-core/go/common"
	commonGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/ias"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/byzantine"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/supplementarysanity"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
	"github.com/oasislabs/oasis-core/go/storage"
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/common/p2p"
	"github.com/oasislabs/oasis-core/go/worker/compute"
	"github.com/oasislabs/oasis-core/go/worker/compute/txnscheduler"
	"github.com/oasislabs/oasis-core/go/worker/keymanager"
	"github.com/oasislabs/oasis-core/go/worker/registration"
	workerSentry "github.com/oasislabs/oasis-core/go/worker/sentry"
	workerGrpcSentry "github.com/oasislabs/oasis-core/go/worker/sentry/grpc"
	workerStorage "github.com/oasislabs/oasis-core/go/worker/storage"
)

type argBuilder struct {
	vec []string
}

func (args *argBuilder) internalSocketAddress(path string) *argBuilder {
	args.vec = append(args.vec, "--"+grpc.CfgAddress, "unix:"+path)
	return args
}

func (args *argBuilder) debugDontBlameOasis() *argBuilder {
	args.vec = append(args.vec, "--"+flags.CfgDebugDontBlameOasis)
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

func (args *argBuilder) consensusValidator() *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + flags.CfgConsensusValidator,
	}...)
	return args
}

func (args *argBuilder) tendermintMinGasPrice(price uint64) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + tendermint.CfgConsensusMinGasPrice, strconv.Itoa(int(price)),
	}...)
	return args
}

func (args *argBuilder) tendermintSubmissionGasPrice(price uint64) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + tendermint.CfgConsensusSubmissionGasPrice, strconv.Itoa(int(price)),
	}...)
	return args
}

func (args *argBuilder) tendermintCoreListenAddress(port uint16) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + tendermint.CfgCoreListenAddress, "tcp://0.0.0.0:" + strconv.Itoa(int(port)),
	}...)
	return args
}

func (args *argBuilder) tendermintSentryUpstreamAddress(addrs []string) *argBuilder {
	for _, addr := range addrs {
		args.vec = append(args.vec, []string{
			"--" + tendermint.CfgSentryUpstreamAddress, addr,
		}...)
	}
	return args
}

func (args *argBuilder) tendermintDisablePeerExchange() *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + tendermint.CfgP2PDisablePeerExchange,
	}...)
	return args
}

func (args *argBuilder) tendermintSeedMode() *argBuilder {
	args.vec = append(args.vec, "--"+tendermint.CfgP2PSeedMode)
	return args
}

func (args *argBuilder) tendermintDebugAddrBookLenient() *argBuilder {
	args.vec = append(args.vec, "--"+tendermint.CfgDebugP2PAddrBookLenient)
	return args
}

func (args *argBuilder) tendermintDebugAllowDuplicateIP() *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + tendermint.CfgDebugP2PAllowDuplicateIP,
	}...)
	return args
}

func (args *argBuilder) storageBackend(backend string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + storage.CfgBackend, backend,
	}...)
	return args
}

func (args *argBuilder) runtimeSupported(id common.Namespace) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + runtimeRegistry.CfgSupported, id.String(),
	}...)
	return args
}

func (args *argBuilder) supplementarysanityEnabled() *argBuilder {
	args.vec = append(args.vec, "--"+supplementarysanity.CfgEnabled)
	args.vec = append(args.vec, []string{
		"--" + supplementarysanity.CfgInterval, "1",
	}...)
	return args
}

func (args *argBuilder) runtimeTagIndexerBackend(backend string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + runtimeRegistry.CfgTagIndexerBackend, backend,
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

func (args *argBuilder) workerCommonSentryCertFiles(certFiles []string) *argBuilder {
	for _, certFile := range certFiles {
		args.vec = append(args.vec, []string{
			"--" + workerCommon.CfgSentryCertFiles, certFile,
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

func (args *argBuilder) workerRuntimeBackend(backend string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerCommon.CfgRuntimeBackend, backend,
	}...)
	return args
}

func (args *argBuilder) workerRuntimeLoader(fn string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerCommon.CfgRuntimeLoader, fn,
	}...)
	return args
}

func (args *argBuilder) workerRuntimeBinary(id common.Namespace, fn string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerCommon.CfgRuntimeBinary, id.String() + ":" + fn,
	}...)
	return args
}

func (args *argBuilder) workerComputeEnabled() *argBuilder {
	args.vec = append(args.vec, "--"+compute.CfgWorkerEnabled)
	return args
}

func (args *argBuilder) workerKeymangerEnabled() *argBuilder {
	args.vec = append(args.vec, "--"+keymanager.CfgEnabled)
	return args
}

func (args *argBuilder) workerKeymanagerRuntimeBinary(fn string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + keymanager.CfgRuntimeBinary, fn,
	}...)
	return args
}

func (args *argBuilder) workerKeymanagerRuntimeLoader(fn string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + keymanager.CfgRuntimeLoader, fn,
	}...)
	return args
}

func (args *argBuilder) workerKeymanagerTEEHardware(hw node.TEEHardware) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + keymanager.CfgTEEHardware, hw.String(),
	}...)
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

func (args *argBuilder) grpcSentryUpstreamCertFiles(certFiles []string) *argBuilder {
	for _, certFile := range certFiles {
		args.vec = append(args.vec, []string{
			"--" + workerGrpcSentry.CfgUpstreamCert, certFile,
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

func (args *argBuilder) workerTxnschedulerCheckTxEnabled() *argBuilder {
	args.vec = append(args.vec, "--"+txnscheduler.CfgCheckTxEnabled)
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
	var addrs, certFiles []string
	for _, sentry := range sentries {
		addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", sentry.controlPort))
		certFiles = append(certFiles, sentry.TLSCertPath())
	}
	return args.workerCommonSentryAddresses(addrs).workerCommonSentryCertFiles(certFiles)
}

func (args *argBuilder) addValidatorsAsSentryUpstreams(validators []*Validator) *argBuilder {
	var addrs []string
	for _, val := range validators {
		addrs = append(addrs, fmt.Sprintf("%s@127.0.0.1:%d", val.tmAddress, val.consensusPort))
	}
	return args.tendermintSentryUpstreamAddress(addrs)
}

func (args *argBuilder) addSentryStorageWorkers(storageWorkers []*Storage) *argBuilder {
	var addrs, certFiles, tmAddrs []string
	for _, storageWorker := range storageWorkers {
		addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", storageWorker.clientPort))
		certFiles = append(certFiles, storageWorker.TLSCertPath())
		tmAddrs = append(tmAddrs, fmt.Sprintf("%s@127.0.0.1:%d", storageWorker.tmAddress, storageWorker.consensusPort))
	}
	return args.grpcSentryUpstreamAddresses(addrs).grpcSentryUpstreamCertFiles(certFiles).tendermintSentryUpstreamAddress(tmAddrs)
}

func (args *argBuilder) addSentryKeymanagerWorkers(keymanagerWorkers []*Keymanager) *argBuilder {
	var addrs, certFiles, tmAddrs []string
	for _, keymanager := range keymanagerWorkers {
		addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", keymanager.workerClientPort))
		certFiles = append(certFiles, keymanager.TLSCertPath())
		tmAddrs = append(tmAddrs, fmt.Sprintf("%s@127.0.0.1:%d", keymanager.tmAddress, keymanager.consensusPort))
	}
	return args.grpcSentryUpstreamAddresses(addrs).grpcSentryUpstreamCertFiles(certFiles).tendermintSentryUpstreamAddress(tmAddrs)
}

func (args *argBuilder) appendSeedNodes(net *Network) *argBuilder {
	if seed := net.seedNode; seed != nil {
		args.vec = append(args.vec, []string{
			"--" + tendermint.CfgP2PSeed, fmt.Sprintf("%s@127.0.0.1:%d", seed.tmAddress, seed.consensusPort),
		}...)
	}
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

func (args *argBuilder) appendComputeNodeRuntime(rt *Runtime) *argBuilder {
	args = args.runtimeSupported(rt.id).
		workerRuntimeBinary(rt.id, rt.binary).
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
			"--" + ias.CfgDebugSkipVerify,
			"--" + ias.CfgAllowDebugEnclaves,
		}...)
	}
	return args
}

func (args *argBuilder) byzantineFakeSGX() *argBuilder {
	args.vec = append(args.vec, "--"+byzantine.CfgFakeSGX)
	return args
}

func (args *argBuilder) byzantineVersionFakeEnclaveID(rt *Runtime) *argBuilder {
	eid := sgx.EnclaveIdentity{
		MrEnclave: *rt.mrEnclave,
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
