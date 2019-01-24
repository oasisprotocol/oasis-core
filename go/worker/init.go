package worker

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/committee"
	"github.com/oasislabs/ekiden/go/worker/enclaverpc"
	"github.com/oasislabs/ekiden/go/worker/ias"
)

const (
	cfgWorkerBackend = "worker.backend"

	cfgWorkerBinary = "worker.binary"

	cfgIASProxy = "worker.ias.proxy_addr"

	cfgKeyManagerAddress = "worker.key_manager.address"
	cfgKeyManagerCert    = "worker.key_manager.certificate"

	cfgRuntimeBinary = "worker.runtime.binary"
	cfgRuntimeID     = "worker.runtime.id"

	// XXX: This is needed until we decide how we want to actually register runtimes.
	cfgRuntimeSGXIDs                 = "worker.runtime.sgx_ids"
	cfgRuntimeReplicaGroupSize       = "worker.runtime.replica_group_size"
	cfgRuntimeReplicaGroupBackupSize = "worker.runtime.replica_group_backup_size"

	cfgMaxQueueSize      = "worker.leader.max_queue_size"
	cfgMaxBatchSize      = "worker.leader.max_batch_size"
	cfgMaxBatchSizeBytes = "worker.leader.max_batch_size_bytes"
	cfgMaxBatchTimeout   = "worker.leader.max_batch_timeout"

	cfgStorageCommitTimeout = "worker.storage_commit_timeout"

	cfgClientPort      = "worker.client.port"
	cfgClientAddresses = "worker.client.addresses"

	cfgP2pPort      = "worker.p2p.port"
	cfgP2pAddresses = "worker.p2p.addresses"

	cfgByzantineInjectDiscrepancies = "worker.byzantine.inject_discrepancies"
)

func parseAddressList(addresses []string) ([]node.Address, error) {
	var output []node.Address
	for _, rawAddress := range addresses {
		rawIP, rawPort, err := net.SplitHostPort(rawAddress)
		if err != nil {
			return nil, fmt.Errorf("malformed address: %s", err)
		}

		port, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("malformed port: %s", rawPort)
		}

		ip := net.ParseIP(rawIP)
		if ip == nil {
			return nil, fmt.Errorf("malformed ip address: %s", rawIP)
		}

		var address node.Address
		if err := address.FromIP(ip, uint16(port)); err != nil {
			return nil, fmt.Errorf("unknown address family: %s", rawIP)
		}

		output = append(output, address)
	}

	return output, nil
}

func getSGXRuntimeIDs() (map[signature.MapKey]bool, error) {
	m := make(map[signature.MapKey]bool)

	for _, v := range viper.GetStringSlice(cfgRuntimeSGXIDs) {
		var id signature.PublicKey
		if err := id.UnmarshalHex(v); err != nil {
			return nil, err
		}

		m[id.ToMapKey()] = true
	}

	return m, nil
}

// New creates a new worker.
func New(
	dataDir string,
	identity *identity.Identity,
	storage storage.Backend,
	roothash roothash.Backend,
	registry registry.Backend,
	epochtime epochtime.Backend,
	scheduler scheduler.Backend,
) (*Worker, error) {
	backend := viper.GetString(cfgWorkerBackend)
	workerBinary := viper.GetString(cfgWorkerBinary)

	// Setup runtimes.
	var runtimes []RuntimeConfig
	runtimeBinaries := viper.GetStringSlice(cfgRuntimeBinary)
	runtimeIDs := viper.GetStringSlice(cfgRuntimeID)
	if len(runtimeBinaries) != len(runtimeIDs) {
		return nil, fmt.Errorf("runtime binary/id count mismatch")
	}

	sgxRuntimeIDs, err := getSGXRuntimeIDs()
	if err != nil {
		return nil, err
	}

	for idx, runtimeBinary := range runtimeBinaries {
		var runtimeID signature.PublicKey
		if err = runtimeID.UnmarshalHex(runtimeIDs[idx]); err != nil {
			return nil, err
		}

		var teeHardware node.TEEHardware
		if sgxRuntimeIDs[runtimeID.ToMapKey()] {
			teeHardware = node.TEEHardwareIntelSGX
		}

		runtimes = append(runtimes, RuntimeConfig{
			ID:          runtimeID,
			Binary:      runtimeBinary,
			TEEHardware: teeHardware,
			// XXX: This is needed until we decide how we want to actually register runtimes.
			ReplicaGroupSize:       uint64(viper.GetInt64(cfgRuntimeReplicaGroupSize)),
			ReplicaGroupBackupSize: uint64(viper.GetInt64(cfgRuntimeReplicaGroupBackupSize)),
		})
	}

	// Create new IAS proxy client.
	iasProxy := viper.GetString(cfgIASProxy)
	ias, err := ias.New(identity, iasProxy)
	if err != nil {
		return nil, err
	}

	// Create new key manager client.
	var keyManager *enclaverpc.Client
	keyManagerAddress := viper.GetString(cfgKeyManagerAddress)
	if keyManagerAddress != "" {
		keyManagerCert := viper.GetString(cfgKeyManagerCert)
		keyManager, err = enclaverpc.NewClient(keyManagerAddress, keyManagerCert, []byte(""))
		if err != nil {
			return nil, err
		}
	}

	maxQueueSize := uint64(viper.GetInt(cfgMaxQueueSize))
	maxBatchSize := uint64(viper.GetInt(cfgMaxBatchSize))
	maxBatchSizeBytes := uint64(viper.GetInt(cfgMaxBatchSizeBytes))
	maxBatchTimeout := viper.GetDuration(cfgMaxBatchTimeout)

	// Parse register address overrides.
	clientAddresses, err := parseAddressList(viper.GetStringSlice(cfgClientAddresses))
	if err != nil {
		return nil, err
	}
	p2pAddresses, err := parseAddressList(viper.GetStringSlice(cfgP2pAddresses))
	if err != nil {
		return nil, err
	}

	cfg := Config{
		Backend: backend,
		Committee: committee.Config{
			MaxQueueSize:      maxQueueSize,
			MaxBatchSize:      maxBatchSize,
			MaxBatchSizeBytes: maxBatchSizeBytes,
			MaxBatchTimeout:   maxBatchTimeout,

			StorageCommitTimeout: viper.GetDuration(cfgStorageCommitTimeout),

			ByzantineInjectDiscrepancies: viper.GetBool(cfgByzantineInjectDiscrepancies),
		},
		ClientPort:      uint16(viper.GetInt(cfgClientPort)),
		ClientAddresses: clientAddresses,
		P2PPort:         uint16(viper.GetInt(cfgP2pPort)),
		P2PAddresses:    p2pAddresses,
		WorkerBinary:    workerBinary,
		Runtimes:        runtimes,
	}

	return newWorker(dataDir, identity, storage, roothash, registry, epochtime, scheduler, ias, keyManager, cfg)
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgWorkerBackend, "sandboxed", "Worker backend")

		cmd.Flags().String(cfgWorkerBinary, "", "Path to worker process binary")

		cmd.Flags().String(cfgIASProxy, "", "IAS proxy address")

		cmd.Flags().String(cfgKeyManagerAddress, "", "key manager address")
		cmd.Flags().String(cfgKeyManagerCert, "", "key manager TLS certificate")

		cmd.Flags().StringSlice(cfgRuntimeBinary, nil, "Path to runtime binary")
		cmd.Flags().StringSlice(cfgRuntimeID, nil, "Runtime ID")

		// XXX: Needed till runtime registration is done elsewhere.
		cmd.Flags().StringSlice(cfgRuntimeSGXIDs, nil, "SGX runtime IDs")
		cmd.Flags().Uint64(cfgRuntimeReplicaGroupSize, 1, "Number of workers in runtime replica group")
		cmd.Flags().Uint64(cfgRuntimeReplicaGroupBackupSize, 0, "Number of backup workers in runtime replica group")

		cmd.Flags().Uint64(cfgMaxQueueSize, 10000, "Maximum size of the incoming queue")
		cmd.Flags().Uint64(cfgMaxBatchSize, 1000, "Maximum size of a batch of runtime requests")
		cmd.Flags().Uint64(cfgMaxBatchSizeBytes, 16777216, "Maximum size (in bytes) of a batch of runtime requests")
		cmd.Flags().Duration(cfgMaxBatchTimeout, 1*time.Second, "Maximum amount of time to wait for a batch")

		cmd.Flags().Duration(cfgStorageCommitTimeout, 5*time.Second, "Storage commit timeout")

		cmd.Flags().Uint16(cfgClientPort, 9100, "Port to use for incoming gRPC client connections")
		cmd.Flags().StringSlice(cfgClientAddresses, []string{}, "Address/port(s) to use for client connections when registering this node (if not set, all non-loopback local interfaces will be used)")

		cmd.Flags().Uint16(cfgP2pPort, 9200, "Port to use for incoming P2P connections")
		cmd.Flags().StringSlice(cfgP2pAddresses, []string{}, "Address/port(s) to use for P2P connections when registering this node (if not set, all non-loopback local interfaces will be used)")

		cmd.Flags().Bool(cfgByzantineInjectDiscrepancies, false, "BYZANTINE: Inject discrepancies into batches")
	}

	for _, v := range []string{
		cfgWorkerBackend,

		cfgWorkerBinary,

		cfgIASProxy,

		cfgKeyManagerAddress,
		cfgKeyManagerCert,

		cfgRuntimeBinary,
		cfgRuntimeID,

		cfgRuntimeSGXIDs,
		cfgRuntimeReplicaGroupSize,
		cfgRuntimeReplicaGroupBackupSize,

		cfgMaxQueueSize,
		cfgMaxBatchSize,
		cfgMaxBatchSizeBytes,
		cfgMaxBatchTimeout,

		cfgStorageCommitTimeout,

		cfgClientPort,
		cfgClientAddresses,

		cfgP2pPort,

		cfgByzantineInjectDiscrepancies,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
