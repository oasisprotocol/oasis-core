package ekiden

import (
	"encoding/hex"
	"path/filepath"
	"strconv"
	"time"

	"github.com/oasislabs/ekiden/go/beacon"
	"github.com/oasislabs/ekiden/go/client"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	commonGrpc "github.com/oasislabs/ekiden/go/common/grpc"
	"github.com/oasislabs/ekiden/go/common/node"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/debug/byzantine"
	"github.com/oasislabs/ekiden/go/epochtime"
	roothashTm "github.com/oasislabs/ekiden/go/roothash/tendermint"
	"github.com/oasislabs/ekiden/go/storage"
	"github.com/oasislabs/ekiden/go/tendermint"
	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
	"github.com/oasislabs/ekiden/go/worker/compute"
	"github.com/oasislabs/ekiden/go/worker/keymanager"
	"github.com/oasislabs/ekiden/go/worker/merge"
	"github.com/oasislabs/ekiden/go/worker/registration"
	workerStorage "github.com/oasislabs/ekiden/go/worker/storage"
	"github.com/oasislabs/ekiden/go/worker/txnscheduler"
	"github.com/oasislabs/ekiden/go/worker/txnscheduler/algorithm/batching"
)

type argBuilder struct {
	vec []string
}

func (args *argBuilder) debugAllowTestKeys() *argBuilder {
	args.vec = append(args.vec, "--"+cmdCommon.CfgDebugAllowTestKeys)
	return args
}

func (args *argBuilder) grpcDebugPort(port uint16) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + grpc.CfgDebugPort, strconv.Itoa(int(port)),
	}...)
	return args
}

func (args *argBuilder) grpcServerPort(port uint16) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + grpc.CfgServerPort, strconv.Itoa(int(port)),
	}...)
	return args
}

func (args *argBuilder) grpcVerboseDebug() *argBuilder {
	args.vec = append(args.vec, "--"+commonGrpc.CfgGRPCVerboseDebug)
	return args
}

func (args *argBuilder) consensusBackend(backend string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + flags.CfgConsensusBackend, backend,
	}...)
	return args
}

func (args *argBuilder) tendermintCoreListenAddress(port uint16) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + tendermint.CfgCoreListenAddress, "tcp://0.0.0.0:" + strconv.Itoa(int(port)),
	}...)
	return args
}

func (args *argBuilder) tendermintConsensusTimeoutCommit(d time.Duration) *argBuilder {
	timeoutCommitMs := int(d / time.Millisecond)
	args.vec = append(args.vec, []string{
		"--" + tendermint.CfgConsensusTimeoutCommit, strconv.Itoa(timeoutCommitMs) + "ms",
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

func (args *argBuilder) epochtimeBackend(backend string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + epochtime.CfgBackend, backend,
	}...)
	return args
}

func (args *argBuilder) epochtimeTendermintInterval(blks uint) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + epochtime.CfgTendermintInterval, strconv.Itoa(int(blks)),
	}...)
	return args
}

func (args *argBuilder) beaconDeterministic(deterministic bool) *argBuilder {
	if deterministic {
		args.vec = append(args.vec, "--"+beacon.CfgDebugDeterministic)
	}
	return args
}

func (args *argBuilder) roothashTendermintIndexBlocks() *argBuilder {
	args.vec = append(args.vec, "--"+roothashTm.CfgIndexBlocks)
	return args
}

func (args *argBuilder) storageBackend(backend string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + storage.CfgBackend, backend,
	}...)
	return args
}

func (args *argBuilder) clientIndexRuntimes(id signature.PublicKey) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + client.CfgIndexRuntimes, id.String(),
	}...)
	return args
}

func (args *argBuilder) workerClientPort(port uint16) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerCommon.CfgClientPort, strconv.Itoa(int(port)),
	}...)
	return args
}

func (args *argBuilder) workerP2pPort(port uint16) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + p2p.CfgP2pPort, strconv.Itoa(int(port)),
	}...)
	return args
}

func (args *argBuilder) workerRuntimeID(id signature.PublicKey) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerCommon.CfgRuntimeID, id.String(),
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

func (args *argBuilder) workerRuntimeBinary(fn string) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + workerCommon.CfgRuntimeBinary, fn,
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

func (args *argBuilder) workerKeymanagerRuntimeID(id signature.PublicKey) *argBuilder {
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

func (args *argBuilder) workerTxnschedulerBatchingMaxBatchSize(sz int) *argBuilder {
	args.vec = append(args.vec, []string{
		"--" + batching.CfgMaxBatchSize, strconv.Itoa(sz),
	}...)
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

func (args *argBuilder) appendSeedNodes(net *Network) *argBuilder {
	if seed := net.seedNode; seed != nil {
		args.vec = append(args.vec, []string{
			"--" + tendermint.CfgP2PSeeds, seed.tmAddress + "@127.0.0.1:" + strconv.Itoa(int(seed.consensusPort)),
		}...)
	}

	return args
}

func (args *argBuilder) appendNetwork(net *Network) *argBuilder {
	args = args.grpcVerboseDebug().
		consensusBackend(net.cfg.ConsensusBackend).
		tendermintConsensusTimeoutCommit(net.cfg.ConsensusTimeoutCommit).
		epochtimeBackend(net.cfg.EpochtimeBackend).
		epochtimeTendermintInterval(net.cfg.EpochtimeTendermintInterval).
		beaconDeterministic(net.cfg.DeterministicIdentities).
		appendSeedNodes(net)
	return args
}

func (args *argBuilder) appendComputeNodeRuntime(rt *Runtime) *argBuilder {
	args = args.workerRuntimeID(rt.id).
		workerRuntimeBinary(rt.binary)
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

func (args *argBuilder) appendIASProxy(ias *iasProxy) *argBuilder {
	if ias != nil {
		args.vec = append(args.vec, []string{
			"--ias.proxy_addr", "127.0.0.1:" + strconv.Itoa(int(ias.grpcPort)),
			"--ias.tls", ias.tlsCertPath(),
			"--ias.debug.skip_verify",
		}...)
	}
	return args
}

func (args *argBuilder) byzantineFakeSGX() *argBuilder {
	args.vec = append(args.vec, "--"+byzantine.CfgFakeSGX)
	return args
}

func (args *argBuilder) byzantineMockEpochtime() *argBuilder {
	args.vec = append(args.vec, "--"+byzantine.CfgMockEpochtime)
	return args
}

func newArgBuilder() *argBuilder {
	return &argBuilder{}
}
