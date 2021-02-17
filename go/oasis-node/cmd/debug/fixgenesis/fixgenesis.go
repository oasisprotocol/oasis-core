// Package fixgenesis implements the fix-genesis command.
package fixgenesis

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const cfgNewGenesis = "genesis.new_file"

var (
	fixGenesisCmd = &cobra.Command{
		Use:   "fix-genesis",
		Short: "fix a genesis document",
		Run:   doFixGenesis,
	}

	newGenesisFlag = flag.NewFlagSet("", flag.ContinueOnError)

	logger = logging.GetLogger("cmd/debug/fix-genesis")
)

type oldDocument struct {
	// Height is the block height at which the document was generated.
	Height int64 `json:"height"`
	// Time is the time the genesis block was constructed.
	Time time.Time `json:"genesis_time"`
	// ChainID is the ID of the chain.
	ChainID string `json:"chain_id"`
	// Registry is the registry genesis state.
	Registry oldRegistryGenesis `json:"registry"`
	// RootHash is the roothash genesis state.
	RootHash roothash.Genesis `json:"roothash"`
	// Staking is the staking genesis state.
	Staking staking.Genesis `json:"staking"`
	// KeyManager is the key manager genesis state.
	KeyManager keymanager.Genesis `json:"keymanager"`
	// Scheduler is the scheduler genesis state.
	Scheduler scheduler.Genesis `json:"scheduler"`
	// Beacon is the beacon genesis state.
	Beacon beacon.Genesis `json:"beacon"`
	// Consensus is the consensus genesis state.
	Consensus consensus.Genesis `json:"consensus"`
	// HaltEpoch is the epoch height at which the network will stop processing
	// any transactions and will halt.
	HaltEpoch beacon.EpochTime `json:"halt_epoch"`
	// Extra data is arbitrary extra data that is part of the
	// genesis block but is otherwise ignored by the protocol.
	ExtraData map[string][]byte `json:"extra_data"`
}

type oldRegistryGenesis struct {
	// Parameters are the registry consensus parameters.
	Parameters registry.ConsensusParameters `json:"params"`

	// Entities is the initial list of entities.
	Entities []*entity.SignedEntity `json:"entities,omitempty"`

	// Runtimes is the initial list of runtimes.
	Runtimes []*oldSignedRuntime `json:"runtimes,omitempty"`
	// SuspendedRuntimes is the list of suspended runtimes.
	SuspendedRuntimes []*oldSignedRuntime `json:"suspended_runtimes,omitempty"`

	// Nodes is the initial list of nodes.
	Nodes []*node.MultiSignedNode `json:"nodes,omitempty"`

	// NodeStatuses is a set of node statuses.
	NodeStatuses map[signature.PublicKey]*registry.NodeStatus `json:"node_statuses,omitempty"`
}

type oldEntityWhitelistRuntimeAdmissionPolicy struct {
	Entities map[signature.PublicKey]bool `json:"entities"`
}

type oldRuntimeAdmissionPolicy struct {
	AnyNode         *registry.AnyNodeRuntimeAdmissionPolicy   `json:"any_node,omitempty"`
	EntityWhitelist *oldEntityWhitelistRuntimeAdmissionPolicy `json:"entity_whitelist,omitempty"`
}

type oldRuntime struct { // nolint: maligned
	cbor.Versioned

	// ID is a globally unique long term identifier of the runtime.
	ID common.Namespace `json:"id"`

	// EntityID is the public key identifying the Entity controlling
	// the runtime.
	EntityID signature.PublicKey `json:"entity_id"`

	// Genesis is the runtime genesis information.
	Genesis registry.RuntimeGenesis `json:"genesis"`

	// Kind is the type of runtime.
	Kind registry.RuntimeKind `json:"kind"`

	// TEEHardware specifies the runtime's TEE hardware requirements.
	TEEHardware node.TEEHardware `json:"tee_hardware"`

	// Version is the runtime version information.
	Version registry.VersionInfo `json:"versions"`

	// KeyManager is the key manager runtime ID for this runtime.
	KeyManager *common.Namespace `json:"key_manager,omitempty"`

	// Executor stores parameters of the executor committee.
	Executor registry.ExecutorParameters `json:"executor,omitempty"`

	// TxnScheduler stores transaction scheduling parameters of the executor
	// committee.
	TxnScheduler registry.TxnSchedulerParameters `json:"txn_scheduler,omitempty"`

	// Storage stores parameters of the storage committee.
	Storage registry.StorageParameters `json:"storage,omitempty"`

	// AdmissionPolicy sets which nodes are allowed to register for this runtime.
	// This policy applies to all roles.
	AdmissionPolicy oldRuntimeAdmissionPolicy `json:"admission_policy"`

	// Staking stores the runtime's staking-related parameters.
	Staking registry.RuntimeStakingParameters `json:"staking,omitempty"`
}

type oldSignedRuntime struct {
	signature.Signed
}

func (s *oldSignedRuntime) Open(context signature.Context, runtime *oldRuntime) error { // nolint: interfacer
	return s.Signed.Open(context, runtime)
}

func doFixGenesis(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	// Load the old genesis document.
	f := flags.GenesisFile()
	raw, err := ioutil.ReadFile(f)
	if err != nil {
		logger.Error("failed to open genesis file",
			"err", err,
		)
		os.Exit(1)
	}

	// Parse as the old format.  At some point all the important things
	// will be versioned, but this is not that time.
	var oldDoc oldDocument
	if err = json.Unmarshal(raw, &oldDoc); err != nil {
		logger.Error("failed to parse old genesis file",
			"err", err,
		)
		os.Exit(1)
	}

	// Actually fix the genesis document.
	newDoc, err := updateGenesisDoc(&oldDoc)
	if err != nil {
		logger.Error("failed to fix genesis document",
			"err", err,
		)
		os.Exit(1)
	}

	// Validate the new genesis document.
	if err = newDoc.SanityCheck(); err != nil {
		logger.Error("new genesis document sanity check failed",
			"err", err,
		)
		os.Exit(1)
	}

	// Write out the new genesis document.
	w, shouldClose, err := cmdCommon.GetOutputWriter(cmd, cfgNewGenesis)
	if err != nil {
		logger.Error("failed to get writer for fixed genesis file",
			"err", err,
		)
		os.Exit(1)
	}
	if shouldClose {
		defer w.Close()
	}
	canonJSON, err := newDoc.CanonicalJSON()
	if err != nil {
		logger.Error("failed to get canonical form of fixed genesis file",
			"err", err,
		)
		os.Exit(1)
	}
	if _, err = w.Write(canonJSON); err != nil {
		logger.Error("failed to write fixed genesis file",
			"err", err,
		)
		os.Exit(1)
	}
}

func convertRuntime(rt *oldRuntime) *registry.Runtime {
	crt := &registry.Runtime{
		ID:              rt.ID,
		EntityID:        rt.EntityID,
		Genesis:         rt.Genesis,
		Kind:            rt.Kind,
		TEEHardware:     rt.TEEHardware,
		Version:         rt.Version,
		KeyManager:      rt.KeyManager,
		Staking:         rt.Staking,
		TxnScheduler:    rt.TxnScheduler,
		GovernanceModel: registry.GovernanceEntity,
		Executor: registry.ExecutorParameters{
			GroupSize:         rt.Executor.GroupSize,
			GroupBackupSize:   rt.Executor.GroupBackupSize,
			AllowedStragglers: rt.Executor.AllowedStragglers,
			RoundTimeout:      rt.Executor.RoundTimeout,
			MaxMessages:       32,
			MinPoolSize:       rt.Executor.GroupSize + rt.Executor.GroupBackupSize,
		},
		Storage: registry.StorageParameters{
			GroupSize:               rt.Storage.GroupSize,
			MinWriteReplication:     rt.Storage.MinWriteReplication,
			MaxApplyWriteLogEntries: rt.Storage.MaxApplyWriteLogEntries,
			MaxApplyOps:             rt.Storage.MaxApplyOps,
			CheckpointInterval:      rt.Storage.CheckpointInterval,
			CheckpointNumKept:       rt.Storage.CheckpointNumKept,
			CheckpointChunkSize:     rt.Storage.CheckpointChunkSize,
			MinPoolSize:             rt.Storage.GroupSize,
		},
	}
	crt.Versioned.V = 2

	if rt.AdmissionPolicy.AnyNode != nil {
		crt.AdmissionPolicy.AnyNode = rt.AdmissionPolicy.AnyNode
	} else if rt.AdmissionPolicy.EntityWhitelist != nil {
		crt.AdmissionPolicy.EntityWhitelist = &registry.EntityWhitelistRuntimeAdmissionPolicy{
			Entities: make(map[signature.PublicKey]registry.EntityWhitelistConfig),
		}
		for e, allowed := range rt.AdmissionPolicy.EntityWhitelist.Entities {
			if allowed {
				crt.AdmissionPolicy.EntityWhitelist.Entities[e] = registry.EntityWhitelistConfig{
					MaxNodes: make(map[node.RolesMask]uint16),
				}
			}
		}
	}

	return crt
}

func updateGenesisDoc(oldDoc *oldDocument) (*genesis.Document, error) {
	// Create the new genesis document template.
	newDoc := &genesis.Document{
		Height:     oldDoc.Height,
		Time:       oldDoc.Time,
		ChainID:    oldDoc.ChainID,
		RootHash:   oldDoc.RootHash,
		Staking:    oldDoc.Staking,
		KeyManager: oldDoc.KeyManager,
		Scheduler:  oldDoc.Scheduler,
		Beacon:     oldDoc.Beacon,
		Consensus:  oldDoc.Consensus,
		HaltEpoch:  oldDoc.HaltEpoch,
		ExtraData:  oldDoc.ExtraData,
	}

	newDoc.RootHash.Parameters.MaxRuntimeMessages = 32

	newDoc.Registry = registry.Genesis{
		Parameters:   oldDoc.Registry.Parameters,
		Entities:     oldDoc.Registry.Entities,
		Nodes:        oldDoc.Registry.Nodes,
		NodeStatuses: oldDoc.Registry.NodeStatuses,
	}

	newDoc.Registry.Parameters.EnableRuntimeGovernanceModels = map[registry.RuntimeGovernanceModel]bool{
		registry.GovernanceEntity:  true,
		registry.GovernanceRuntime: true, // TODO: Do we want to enable this right away?
	}

	oldRegisterRuntimeSignatureContext := signature.NewContext("oasis-core/registry: register runtime")

	for _, sigRt := range oldDoc.Registry.Runtimes {
		var rt oldRuntime
		if err := sigRt.Open(oldRegisterRuntimeSignatureContext, &rt); err != nil {
			return nil, fmt.Errorf("unable to open signed runtime: %w", err)
		}
		newRt := convertRuntime(&rt)
		if newRt == nil {
			return nil, fmt.Errorf("unable to convert runtime to new format")
		}
		newDoc.Registry.Runtimes = append(newDoc.Registry.Runtimes, newRt)
	}

	for _, sigSRt := range oldDoc.Registry.SuspendedRuntimes {
		var srt oldRuntime
		if err := sigSRt.Open(oldRegisterRuntimeSignatureContext, &srt); err != nil {
			return nil, fmt.Errorf("unable to open signed suspended runtime: %w", err)
		}
		newSRt := convertRuntime(&srt)
		if newSRt == nil {
			return nil, fmt.Errorf("unable to convert suspended runtime to new format")
		}
		newDoc.Registry.SuspendedRuntimes = append(newDoc.Registry.SuspendedRuntimes, newSRt)
	}

	return newDoc, nil
}

// Register registers the fix-genesis sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	fixGenesisCmd.PersistentFlags().AddFlagSet(flags.GenesisFileFlags)
	fixGenesisCmd.PersistentFlags().AddFlagSet(newGenesisFlag)
	parentCmd.AddCommand(fixGenesisCmd)
}

func init() {
	newGenesisFlag.String(cfgNewGenesis, "genesis_fixed.json", "path to fixed genesis document")
	_ = viper.BindPFlags(newGenesisFlag)
}
