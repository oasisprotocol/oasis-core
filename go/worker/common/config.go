package common

import (
	"context"
	"fmt"
	"os"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	runtimeHost "github.com/oasisprotocol/oasis-core/go/runtime/host"
	hostMock "github.com/oasisprotocol/oasis-core/go/runtime/host/mock"
	hostProtocol "github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	hostSandbox "github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox"
	hostSgx "github.com/oasisprotocol/oasis-core/go/runtime/host/sgx"
	"github.com/oasisprotocol/oasis-core/go/worker/common/configparser"
)

var (
	// CfgClientPort configures the worker client port.
	CfgClientPort = "worker.client.port"

	cfgClientAddresses = "worker.client.addresses"

	// CfgSentryAddresses configures addresses and public keys of sentry nodes the worker should
	// connect to.
	CfgSentryAddresses = "worker.sentry.address"

	// CfgRuntimeProvisioner configures the runtime provisioner.
	CfgRuntimeProvisioner = "worker.runtime.provisioner"
	// CfgRuntimeSGXLoader configures the runtime loader binary required for SGX runtimes. A single
	// loader is used for all runtimes.
	CfgRuntimeSGXLoader = "worker.runtime.sgx.loader"
	// CfgRuntimePaths confgures the paths for supported runtimes. The value should be a map of
	// runtime IDs to corresponding resource paths (type of the resource depends on the
	// provisioner).
	CfgRuntimePaths = "worker.runtime.paths"
	// CfgRuntimeSGXSignatures configures signatures for supported runtimes.
	// The value should be a map of runtime IDs to corresponding resource
	// paths.
	CfgRuntimeSGXSignatures = "worker.runtime.sgx.signatures"

	cfgSandboxBinary        = "worker.runtime.sandbox_binary"
	cfgStorageCommitTimeout = "worker.storage_commit_timeout"

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

const (
	// RuntimeProvisionerMock is the name of the mock runtime provisioner.
	//
	// Use of this provisioner is only allowed if DebugDontBlameOasis flag is set.
	RuntimeProvisionerMock = "mock"
	// RuntimeProvisionerUnconfined is the name of the unconfined runtime provisioner that executes
	// runtimes as regular processes without any sandboxing.
	//
	// Use of this provisioner is only allowed if DebugDontBlameOasis flag is set.
	RuntimeProvisionerUnconfined = "unconfined"
	// RuntimeProvisionerSandboxed is the name of the sandboxed runtime provisioner that executes
	// runtimes as regular processes in a Linux namespaces/cgroups/SECCOMP sandbox.
	RuntimeProvisionerSandboxed = "sandboxed"
)

// Config contains common worker config.
type Config struct { // nolint: maligned
	ClientPort      uint16
	ClientAddresses []node.Address
	SentryAddresses []node.TLSAddress

	// RuntimeHost contains configuration for a worker that hosts runtimes. It may be nil if the
	// worker is not configured to host runtimes.
	RuntimeHost *RuntimeHostConfig

	StorageCommitTimeout time.Duration

	logger *logging.Logger
}

// RuntimeHostConfig is configuration for a worker that hosts runtimes.
type RuntimeHostConfig struct {
	// Provisioners contains a set of supported runtime provisioners, based on TEE hardware.
	Provisioners map[node.TEEHardware]runtimeHost.Provisioner

	// Runtimes contains per-runtime provisioning configuration. Some fields may be omitted as they
	// are provided when the runtime is provisioned.
	Runtimes map[common.Namespace]runtimeHost.Config
}

// GetNodeAddresses returns worker node addresses.
func (c *Config) GetNodeAddresses() ([]node.Address, error) {
	var addresses []node.Address

	if len(c.ClientAddresses) > 0 {
		addresses = c.ClientAddresses
	} else {
		// Use all non-loopback addresses of this node.
		addrs, err := common.FindAllAddresses()
		if err != nil {
			c.logger.Error("failed to obtain addresses",
				"err", err)
			return nil, err
		}
		var address node.Address
		for _, addr := range addrs {
			if derr := address.FromIP(addr, c.ClientPort); derr != nil {
				continue
			}
			addresses = append(addresses, address)
		}
	}
	return addresses, nil
}

// NewConfig creates a new worker config.
func NewConfig(consensus consensus.Backend, ias ias.Endpoint) (*Config, error) {
	// Parse register address overrides.
	clientAddresses, err := configparser.ParseAddressList(viper.GetStringSlice(cfgClientAddresses))
	if err != nil {
		return nil, err
	}

	// Parse sentry configuration.
	var sentryAddresses []node.TLSAddress
	for _, v := range viper.GetStringSlice(CfgSentryAddresses) {
		var tlsAddr node.TLSAddress
		if err = tlsAddr.UnmarshalText([]byte(v)); err != nil {
			return nil, fmt.Errorf("worker: bad sentry address (%s): %w", v, err)
		}
		sentryAddresses = append(sentryAddresses, tlsAddr)
	}

	cfg := Config{
		ClientPort:           uint16(viper.GetInt(CfgClientPort)),
		ClientAddresses:      clientAddresses,
		SentryAddresses:      sentryAddresses,
		StorageCommitTimeout: viper.GetDuration(cfgStorageCommitTimeout),
		logger:               logging.GetLogger("worker/config"),
	}

	// Check if any runtimes are configured to be hosted.
	if viper.IsSet(CfgRuntimePaths) {
		var rh RuntimeHostConfig

		// Configure host environment information.
		cs, err := consensus.GetStatus(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to get consensus layer status: %w", err)
		}
		hostInfo := &hostProtocol.HostInfo{
			ConsensusBackend:         cs.Backend,
			ConsensusProtocolVersion: cs.Version.ToU64(),
		}

		// Register provisioners based on the configured provisioner.
		var insecureNoSandbox bool
		sandboxBinary := viper.GetString(cfgSandboxBinary)
		rh.Provisioners = make(map[node.TEEHardware]runtimeHost.Provisioner)
		switch p := viper.GetString(CfgRuntimeProvisioner); p {
		case RuntimeProvisionerMock:
			// Mock provisioner, only supported when the runtime requires no TEE hardware.
			if !cmdFlags.DebugDontBlameOasis() {
				return nil, fmt.Errorf("mock provisioner requires use of unsafe debug flags")
			}

			rh.Provisioners[node.TEEHardwareInvalid] = hostMock.New()
		case RuntimeProvisionerUnconfined:
			// Unconfined provisioner, can be used with no TEE or with Intel SGX.
			if !cmdFlags.DebugDontBlameOasis() {
				return nil, fmt.Errorf("unconfined provisioner requires use of unsafe debug flags")
			}

			insecureNoSandbox = true

			fallthrough
		case RuntimeProvisionerSandboxed:
			if !insecureNoSandbox {
				if _, err = os.Stat(sandboxBinary); err != nil {
					return nil, fmt.Errorf("failed to stat sandbox binary: %w", err)
				}
			}
			// Sandboxed provisioner, can be used with no TEE or with Intel SGX.
			rh.Provisioners[node.TEEHardwareInvalid], err = hostSandbox.New(hostSandbox.Config{
				HostInfo:          hostInfo,
				InsecureNoSandbox: insecureNoSandbox,
				SandboxBinaryPath: sandboxBinary,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create runtime provisioner: %w", err)
			}

			rh.Provisioners[node.TEEHardwareIntelSGX], err = hostSgx.New(hostSgx.Config{
				HostInfo:          hostInfo,
				LoaderPath:        viper.GetString(CfgRuntimeSGXLoader),
				IAS:               ias,
				SandboxBinaryPath: sandboxBinary,
				InsecureNoSandbox: insecureNoSandbox,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create SGX runtime provisioner: %w", err)
			}
		default:
			return nil, fmt.Errorf("unsupported runtime provisioner: %s", p)
		}

		// Configure runtimes.
		runtimeSGXSignatures := viper.GetStringMapString(CfgRuntimeSGXSignatures)
		rh.Runtimes = make(map[common.Namespace]runtimeHost.Config)
		for runtimeID, path := range viper.GetStringMapString(CfgRuntimePaths) {
			var id common.Namespace
			if err := id.UnmarshalHex(runtimeID); err != nil {
				return nil, fmt.Errorf("bad runtime identifier '%s': %w", runtimeID, err)
			}

			runtimeHostCfg := runtimeHost.Config{
				RuntimeID: id,
				Path:      path,
			}

			// This config is SGX specific, but that's all that's supported
			// right now that needs this anyway, the non-SGX provisioner
			// currently ignores this.
			if sigPath := runtimeSGXSignatures[runtimeID]; sigPath != "" {
				runtimeHostCfg.Extra = &hostSgx.RuntimeExtra{
					SignaturePath: sigPath,
				}
			} else {
				// HACK HACK HACK: Allow dummy SIGSTRUCT generation.
				runtimeHostCfg.Extra = &hostSgx.RuntimeExtra{
					UnsafeDebugGenerateSigstruct: true,
				}
			}

			rh.Runtimes[id] = runtimeHostCfg
		}
		if len(rh.Runtimes) == 0 {
			return nil, fmt.Errorf("no runtimes configured")
		}

		cfg.RuntimeHost = &rh
	}

	return &cfg, nil
}

func init() {
	Flags.Uint16(CfgClientPort, 9100, "Port to use for incoming gRPC client connections")
	Flags.StringSlice(cfgClientAddresses, []string{}, "Address/port(s) to use for client connections when registering this node (if not set, all non-loopback local interfaces will be used)")
	Flags.StringSlice(CfgSentryAddresses, []string{}, "Address(es) of sentry node(s) to connect to of the form [PubKey@]ip:port (where PubKey@ part represents base64 encoded node TLS public key)")

	Flags.String(CfgRuntimeProvisioner, RuntimeProvisionerSandboxed, "Runtime provisioner to use")
	Flags.String(CfgRuntimeSGXLoader, "", "(for SGX runtimes) Path to SGXS runtime loader binary")
	Flags.StringToString(CfgRuntimePaths, nil, "Paths to runtime resources (format: <rt1-ID>=<path>,<rt2-ID>=<path>)")
	Flags.StringToString(CfgRuntimeSGXSignatures, nil, "(for SGX runtimes) Paths to signatures (format: <rt1-ID>=<path>,<rt2-ID>=<path>")

	Flags.String(cfgSandboxBinary, "/usr/bin/bwrap", "Path to the sandbox binary (bubblewrap)")

	Flags.Duration(cfgStorageCommitTimeout, 5*time.Second, "Storage commit timeout")

	_ = viper.BindPFlags(Flags)
}
