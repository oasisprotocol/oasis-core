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
	"github.com/oasislabs/oasis-core/go/worker/keymanager"
	"github.com/oasislabs/oasis-core/go/worker/merge"
	"github.com/oasislabs/oasis-core/go/worker/registration"
	workerSentry "github.com/oasislabs/oasis-core/go/worker/sentry"
	workerStorage "github.com/oasislabs/oasis-core/go/worker/storage"
	"github.com/oasislabs/oasis-core/go/worker/txnscheduler"
)

type argBuilder struct {
	vec []string
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

func (args *argBuilder) tendermintCoreListenAddress(port uint16) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + tendermint.CfgCoreListenAddress, "tcp://0.0.0.0:" + strconv.Itoa(int(port)),
	}...)
	return args
}

func (args *argBuilder) tendermintPersistentPeer(peers []string) *argBuilder {
	for _, peer := range peers {
		args.vec = append(args.vec, []string{
			"--" + tendermint.CfgP2PPersistentPeer, peer,
		}...)
	}
	return args
}

func (args *argBuilder) tendermintPrivatePeerID(peerIDs []string) *argBuilder {
	for _, peerID := range peerIDs {
		args.vec = append(args.vec, []string{
			"--" + tendermint.CfgP2PPrivatePeerID, peerID,
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

func (args *argBuilder) workerMergeEnabled() *argBuilder {
	args.vec = append(args.vec, "--"+merge.CfgWorkerEnabled)
	return args
}

func (args *argBuilder) workerSentryEnabled() *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerSentry.CfgEnabled,
	}...)
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

func (args *argBuilder) workerTxnschedulerEnabled() *argBuilder {
	args.vec = append(args.vec, "--"+txnscheduler.CfgWorkerEnabled)
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
	args = args.workerCommonSentryAddresses(addrs)
	args = args.workerCommonSentryCertFiles(certFiles)
	return args
}

func (args *argBuilder) addSentriesAsPersistentPeers(sentries []*Sentry) *argBuilder {
	var peers []string
	for _, sentry := range sentries {
		peers = append(peers, fmt.Sprintf("%s@127.0.0.1:%d", sentry.tmAddress, sentry.consensusPort))
	}
	args = args.tendermintPersistentPeer(peers)
	return args
}

func (args *argBuilder) addValidatorsAsPrivatePeers(validators []*Validator) *argBuilder {
	var peerIDs []string
	for _, val := range validators {
		peerIDs = append(peerIDs, val.tmAddress)
	}
	args = args.tendermintPrivatePeerID(peerIDs)
	return args
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
	args = args.grpcLogDebug().
		appendSeedNodes(net)
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
			"--" + registration.CfgRegistrationPrivateKey, filepath.Join(dir, "entity.pem"),
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

func newArgBuilder() *argBuilder {
	return &argBuilder{}
}
