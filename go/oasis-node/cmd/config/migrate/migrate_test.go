package migrate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/oasisprotocol/oasis-core/go/config"
	rtConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
)

// Simple test configuration file.
const testSimpleConfigRaw = `
datadir: /node/data

log:
  level:
    default: debug
    tendermint: debug
    tendermint/context: error
  format: JSON

genesis:
  file: /node/etc/genesis.json

consensus:
  tendermint:
    p2p:
      seed:
        - "E27F6B7A350B4CC2B48A6CBE94B0A02B0DCB0BF3@35.199.49.168:26656"

runtime:
  mode: client
  paths:
    - /node/runtime/cipher-paratime-2.6.2.orc
    - /node/runtime/emerald-paratime-10.0.0.orc
    - /node/runtime/sapphire-paratime-0.4.0.orc

worker:
  storage:
    checkpointer:
      enabled: true
`

// Test configuration file with as many options as possible.
// Note that this configuration isn't meant to actually work,
// we're just testing the parsing.
const testComplexConfigRaw = `
datadir: /storage/node

# Logging.
log:
  file: /storage/node/log.txt
  level:
    default: debug
    tendermint: warn
    tendermint/context: error
  format: JSON

# Genesis.
genesis:
  file: /storage/node/genesis.json

# Worker configuration.
worker:
  p2p:
    port: 9002
    peer_outbound_queue_size: 42
    validate_queue_size: 43
    validate_concurrency: 44
    validate_throttle: 45
    max_num_peers: 46
    peer_grace_period: 47s
    connectedness_low_water: 48
    persistent_peers:
      - "foo@1.2.3.4:4321"
    blocked_peers:
      - "1.2.3.4"

  registration:
    entity: /storage/node/entity/entity.json

  tx_pool:
    schedule_max_tx_pool_size: 10000

  storage:
    backend: "badger"
    checkpoint_sync:
      disabled: true
    checkpointer:
      enabled: true

# IAS configuration.
ias:
  proxy:
    address:
      - "qwerty@1.2.3.4:4321"

# Consensus backend.
consensus:
  validator: true

  # Tendermint backend configuration.
  tendermint:
    abci:
      prune:
        strategy: keep_n
        num_kept: 86400
    core:
      listen_address: tcp://0.0.0.0:26656
      external_address: tcp://4.3.2.1:26656
    debug:
      addr_book_lenient: false
    sentry:
      upstream_address:
        - "asdf@1.2.3.4:5678"
    mode: full

    # Validators behind sentry nodes should set sentries as persistent peers.
    p2p:
      # Seed node setup.
      seed:
        - "53572F689E5BACDD3C6527E6594EC49C8F3093F6@34.86.165.6:26656"

      persistent_peer:
        - "asdf@1.2.3.4:5678"

      unconditional_peer:
        - "53572F689E5BACDD3C6527E6594EC49C8F3093F6@34.86.165.6:26656"

      disable_peer_exchange: true

    state_sync:
      enabled: false
      trust_height: 4692334
      trust_hash: "2d9dd35e7254a6c5c87f49d0646ee359f06f460b72278ad3ac17130bd9a7ec19"
      consensus_node:
        - "xAMjfJDcUFUcwgZGEQuOdux8gAdc+IFEqccB2LHdGjU=@34.86.145.181:9001"
        - "DbYomffhISzQ4Nd6O2RX0PBPzbt0U8996IjH4oifOPM=@35.221.19.64:9001"


runtime:
  mode: "client"
  environment: sgx
  provisioner: sandboxed

  history:
    pruner:
      strategy: keep_last

  sgx:
    loader: /oasis/bin/oasis-core-runtime-loader

  paths:
    - /oasis/runtimes/sapphire-paratime.orc
    - /oasis/runtimes/sapphire-paratime-previous.orc

  config:
    "000000000000000000000000000000000000000000000000f80306c9858e7279": {"allow_expensive_queries": true}

# Profiling.
pprof:
  bind: 0.0.0.0:6666

# Metrics.
metrics:
  mode: pull
  address: 0.0.0.0:9101
  job_name: node-mainnet
  interval: 10s
  labels:
    instance: asdf-instance-0
`

// Keymanager test configuration file.
const testKMConfigRaw = `
datadir: /km/data

log:
  level: debug
  format: JSON

genesis:
  file: /km/etc/genesis.json

worker:
  p2p:
    port: 1234
    addresses:
      - "4.3.2.1:26656"
  registration:
    entity: /km/etc/entity/entity.json
  keymanager:
    may_generate: false
    runtime:
      id: "4000000000000000000000000000000000000000000000004a1a53dff2ae482d"
    private_peer_pub_keys:
      - "asdf"
      - "ghij"
      - "klmn"

ias:
  proxy:
    address:
      - "foo@1.2.3.4:5678"

consensus:
  validator: false
  tendermint:
    mode: full
    core:
      listen_address: tcp://0.0.0.0:26656
      external_address: tcp://4.3.2.1:26656
    p2p:
      seed:
        - "asdf@1.2.3.4:26656"

runtime:
  mode: "keymanager"
  environment: sgx
  provisioner: sandboxed
  sgx:
    loader: /km/bin/oasis-core-runtime-loader
  paths:
    - /km/runtimes/keymanager.orc
`

// Validator node.
const testValidatorConfigRaw = `
datadir: /node/data

log:
  level:
    default: info
    tendermint: info
    tendermint/context: error
  format: JSON

genesis:
  file: /node/etc/genesis.json

consensus:
  validator: true

  tendermint:
    p2p:
      # List of seed nodes to connect to.
      # NOTE: You can add additional seed nodes to this list if you want.
      seed:
        - "E27F6B7A350B4CC2B48A6CBE94B0A02B0DCB0BF3@35.199.49.168:26656"

worker:
  registration:
    # In order for the node to register itself, the entity.json of the entity
    # used to provision the node must be available on the node.
    entity: /node/entity/entity.json
`

// Validator node with external address set and no P2P address.
const testValidatorConfig2Raw = `
datadir: /node/data

log:
  level:
    default: info
    tendermint: info
    tendermint/context: error
  format: JSON

genesis:
  file: /node/etc/genesis.json

consensus:
  validator: true

  tendermint:
    p2p:
      # List of seed nodes to connect to.
      # NOTE: You can add additional seed nodes to this list if you want.
      seed:
        - "E27F6B7A350B4CC2B48A6CBE94B0A02B0DCB0BF3@35.199.49.168:26656"
    core:
      external_address: tcp://4.3.2.1:26656

worker:
  registration:
    # In order for the node to register itself, the entity.json of the entity
    # used to provision the node must be available on the node.
    entity: /node/entity/entity.json
`

// Non-validator node from docs test configuration file.
const testDocsNonValidatorConfigRaw = `
datadir: /node/data

log:
  level:
    default: info
    tendermint: info
    tendermint/context: error
  format: JSON

genesis:
  file: /node/etc/genesis.json

consensus:
  tendermint:
    p2p:
      # List of seed nodes to connect to.
      # NOTE: You can add additional seed nodes to this list if you want.
      seed:
        - "E27F6B7A350B4CC2B48A6CBE94B0A02B0DCB0BF3@35.199.49.168:26656"
`

// Seed node from docs test configuration file.
const testDocsSeedConfigRaw = `
datadir: /node/data

log:
  level:
    default: info
    tendermint: info
    tendermint/context: error
  format: JSON

genesis:
  file: /node/etc/genesis.json

consensus:
  tendermint:
    mode: seed
`

// Archive node from docs test configuration file.
const testDocsArchiveConfigRaw = `
datadir: /node/data

log:
  level:
    default: info
    tendermint: info
    tendermint/context: error
  format: JSON

genesis:
  file: /node/etc/genesis.json

consensus:
  tendermint:
    mode: archive
`

// ParaTime node from docs test configuration file.
const testDocsParaTimeConfigRaw = `
datadir: /node/data

log:
  level:
    default: info
    tendermint: info
    tendermint/context: error
  format: JSON

genesis:
  file: /node/etc/genesis.json

consensus:
  tendermint:
    core:
      listen_address: tcp://0.0.0.0:26656

      # The external IP that is used when registering this node to the network.
      # NOTE: If you are using the Sentry node setup, this option should be
      # omitted.
      external_address: tcp://1.2.3.4:26656

    p2p:
      # List of seed nodes to connect to.
      # NOTE: You can add additional seed nodes to this list if you want.
      seed:
        - "E27F6B7A350B4CC2B48A6CBE94B0A02B0DCB0BF3@35.199.49.168:26656"

runtime:
  mode: compute
  paths:
    # Paths to ParaTime bundles for all of the supported ParaTimes.
    - /node/runtimes/test.orc

  # The following section is required for ParaTimes which are running inside the
  # Intel SGX Trusted Execution Environment.
  sgx:
    loader: /node/bin/oasis-core-runtime-loader

worker:
  registration:
    # In order for the node to register itself, the entity.json of the entity
    # used to provision the node must be available on the node.
    entity: /node/entity/entity.json

  p2p:
    # External P2P configuration.
    port: 30002
    addresses:
      # The external IP that is used when registering this node to the network.
      - "1.2.3.4:30002"

# The following section is required for ParaTimes which are running inside the
# Intel SGX Trusted Execution Environment.
ias:
  proxy:
    address:
      # List of IAS proxies to connect to.
      # NOTE: You can add additional IAS proxies to this list if you want.
      - "asdf@5.4.3.2:1234"
`

// ParaTime client node from docs test configuration file.
const testDocsParaTimeClientConfigRaw = `
datadir: /node/data

log:
  level:
    default: info
    tendermint: info
    tendermint/context: error
  format: JSON

genesis:
  file: /node/etc/genesis.json

consensus:
  tendermint:
    p2p:
      # List of seed nodes to connect to.
      # NOTE: You can add additional seed nodes to this list if you want.
      seed:
        - "E27F6B7A350B4CC2B48A6CBE94B0A02B0DCB0BF3@35.199.49.168:26656"

runtime:
  mode: client
  paths:
    # Paths to ParaTime bundles for all of the supported ParaTimes.
    - "/node/runtimes/test.orc"
`

// Sentry node from docs test configuration file.
const testDocsSentryConfigRaw = `
datadir: /serverdir/node

log:
  level:
    default: debug
    tendermint: warn
    tendermint/context: error
  format: JSON

genesis:
  file: /serverdir/etc/genesis.json

worker:
  sentry:
    enabled: true
    control:
      port: 9009
      authorized_pubkey:
        - asdf

consensus:
  tendermint:
    abci:
      prune:
        strategy: keep_n
        # Keep ~1 hour of data since block production is ~1 block every 6 seconds.
        # (3600/6 = 600)
        num_kept: 600
    core:
      listen_address: tcp://0.0.0.0:26656
      external_address: tcp://6.7.8.9:26656

    p2p:
      seed:
        - "E27F6B7A350B4CC2B48A6CBE94B0A02B0DCB0BF3@35.199.49.168:26656"

    sentry:
      upstream_address:
        - "asdf@1.2.3.4:26656"
`

// Simple config with internal socket override.
const testInternalSocketOverrideConfigRaw = `
debug:
  dont_blame_oasis: true
  grpc:
    internal:
      socket_path: /node/custom-internal.sock

datadir: /node/data

log:
  level:
    default: debug
    tendermint: debug
    tendermint/context: error
  format: JSON

genesis:
  file: /node/etc/genesis.json

consensus:
  tendermint:
    p2p:
      seed:
        - "E27F6B7A350B4CC2B48A6CBE94B0A02B0DCB0BF3@35.199.49.168:26656"

runtime:
  mode: client
  paths:
    - /node/runtime/cipher-paratime-2.6.2.orc
    - /node/runtime/emerald-paratime-10.0.0.orc
    - /node/runtime/sapphire-paratime-0.4.0.orc

worker:
  storage:
    checkpointer:
      enabled: true
`

func prepareTest(require *require.Assertions, configIn string) config.Config {
	// Prepare temporary directory and populate it with the test config file.
	tempDir, err := os.MkdirTemp("", "oasis-node-config_migrate_test_")
	require.NoError(err, "failed to create temp dir")
	defer os.RemoveAll(tempDir)

	inFile := filepath.Join(tempDir, "config.yaml")
	outFile := filepath.Join(tempDir, "config_new.yaml")

	err = os.WriteFile(inFile, []byte(configIn), 0o600)
	require.NoError(err, "failed to write test config file")

	// Run the migration command.
	cmd := migrateCmd
	viper.Set(cfgIn, inFile)
	viper.Set(cfgOut, outFile)
	require.NoError(cmd.Execute(), "migration failed")

	// Parse migrated config file.
	newConfigRaw, err := os.ReadFile(outFile)
	require.NoError(err, "failed to read migrated config file")

	newConfig := config.DefaultConfig()
	err = yaml.Unmarshal(newConfigRaw, &newConfig)
	require.NoError(err, "failed to unmarshal migrated config file")

	err = newConfig.Validate()
	require.NoError(err, "failed to validate migrated config file")

	return newConfig
}

func TestConfigMigrationSimple(t *testing.T) {
	require := require.New(t)
	newConfig := prepareTest(require, testSimpleConfigRaw)

	// Now check if the config struct fields actually match the original state.
	require.Equal(newConfig.Mode, config.ModeClient)
	require.Equal(newConfig.Common.DataDir, "/node/data")
	require.Equal(newConfig.Common.Log.Format, "JSON")
	require.Equal(newConfig.Common.Log.Level["default"], "debug")
	require.Equal(newConfig.Common.Log.Level["cometbft"], "debug")
	require.Equal(newConfig.Common.Log.Level["cometbft/context"], "error")
	require.Equal(newConfig.Genesis.File, "/node/etc/genesis.json")
	require.Equal(newConfig.P2P.Seeds[0], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:26656")
	require.Equal(newConfig.P2P.Seeds[1], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:9200")
	require.Equal(newConfig.Runtime.Paths[0], "/node/runtime/cipher-paratime-2.6.2.orc")
	require.Equal(newConfig.Runtime.Paths[1], "/node/runtime/emerald-paratime-10.0.0.orc")
	require.Equal(newConfig.Runtime.Paths[2], "/node/runtime/sapphire-paratime-0.4.0.orc")
	require.Equal(newConfig.Storage.Checkpointer.Enabled, true)
}

func TestConfigMigrationComplex(t *testing.T) {
	require := require.New(t)
	newConfig := prepareTest(require, testComplexConfigRaw)

	// Now check if the config struct fields actually match the original state.
	require.Equal(newConfig.Mode, config.ModeClient)
	require.Equal(newConfig.Common.DataDir, "/storage/node")
	require.Equal(newConfig.Common.Log.File, "/storage/node/log.txt")
	require.Equal(newConfig.Common.Log.Format, "JSON")
	require.Equal(newConfig.Common.Log.Level["default"], "debug")
	require.Equal(newConfig.Common.Log.Level["cometbft"], "warn")
	require.Equal(newConfig.Common.Log.Level["cometbft/context"], "error")
	require.Equal(newConfig.Genesis.File, "/storage/node/genesis.json")
	require.Equal(newConfig.P2P.Port, uint16(9002))
	require.Equal(newConfig.P2P.Seeds[0], "HcDFrTp/MqRHtju5bCx6TIhIMd6X/0ZQ3lUG73q5898=@34.86.165.6:26656")
	require.Equal(newConfig.P2P.Seeds[1], "HcDFrTp/MqRHtju5bCx6TIhIMd6X/0ZQ3lUG73q5898=@34.86.165.6:9200")
	require.Equal(newConfig.P2P.Gossipsub.PeerOutboundQueueSize, 42)
	require.Equal(newConfig.P2P.Gossipsub.ValidateQueueSize, 43)
	require.Equal(newConfig.P2P.Gossipsub.ValidateConcurrency, 44)
	require.Equal(newConfig.P2P.Gossipsub.ValidateThrottle, 45)
	require.Equal(newConfig.P2P.ConnectionManager.MaxNumPeers, 46)
	require.Equal(newConfig.P2P.ConnectionManager.PeerGracePeriod, 47*time.Second)
	require.Equal(newConfig.P2P.ConnectionManager.PersistentPeers[0], "foo@1.2.3.4:4321")
	require.Equal(newConfig.P2P.ConnectionGater.BlockedPeerIPs[0], "1.2.3.4")
	require.Equal(newConfig.P2P.PeerManager.ConnectednessLowWater, 48.0)
	require.Equal(newConfig.Consensus.P2P.PersistentPeer[0], "INSERT_P2P_PUBKEY_HERE@1.2.3.4:5678")
	require.Equal(newConfig.Consensus.P2P.UnconditionalPeer[0], "HcDFrTp/MqRHtju5bCx6TIhIMd6X/0ZQ3lUG73q5898=@34.86.165.6:26656")
	require.Equal(newConfig.Consensus.SentryUpstreamAddresses[0], "INSERT_P2P_PUBKEY_HERE@1.2.3.4:5678")
	require.Equal(newConfig.IAS.ProxyAddresses, []string{"qwerty@1.2.3.4:4321"})
	require.Equal(newConfig.Pprof.BindAddress, "0.0.0.0:6666")
	require.Equal(newConfig.Runtime.Environment, rtConfig.RuntimeEnvironmentSGX)
	require.Equal(newConfig.Runtime.Provisioner, rtConfig.RuntimeProvisionerSandboxed)
	require.Equal(newConfig.Runtime.Prune.Strategy, "keep_last")
	require.Equal(newConfig.Runtime.SGXLoader, "/oasis/bin/oasis-core-runtime-loader")
	require.Equal(newConfig.Runtime.Paths[0], "/oasis/runtimes/sapphire-paratime.orc")
	require.Equal(newConfig.Runtime.Paths[1], "/oasis/runtimes/sapphire-paratime-previous.orc")
	_, hasConfigKey := newConfig.Runtime.RuntimeConfig["000000000000000000000000000000000000000000000000f80306c9858e7279"]
	require.Equal(hasConfigKey, true)
	require.Equal(newConfig.Runtime.TxPool.MaxPoolSize, uint64(10000))
	require.Equal(newConfig.Consensus.ListenAddress, "tcp://0.0.0.0:26656")
	require.Equal(newConfig.Consensus.ExternalAddress, "tcp://4.3.2.1:26656")
	require.Equal(newConfig.Consensus.Validator, true)
	require.Equal(newConfig.Consensus.P2P.DisablePeerExchange, true)
	require.Equal(newConfig.Consensus.Prune.Strategy, "keep_n")
	require.Equal(newConfig.Consensus.Prune.NumKept, uint64(86400))
	require.Equal(newConfig.Consensus.StateSync.Enabled, false)
	require.Equal(newConfig.Consensus.StateSync.TrustPeriod, 24*time.Hour)
	require.Equal(newConfig.Consensus.StateSync.TrustHeight, uint64(4692334))
	require.Equal(newConfig.Consensus.StateSync.TrustHash, "2d9dd35e7254a6c5c87f49d0646ee359f06f460b72278ad3ac17130bd9a7ec19")
	require.Equal(newConfig.Storage.Backend, "badger")
	require.Equal(newConfig.Storage.CheckpointSyncDisabled, true)
	require.Equal(newConfig.Storage.Checkpointer.Enabled, true)
	require.Equal(newConfig.Registration.Entity, "/storage/node/entity/entity.json")
	require.Equal(newConfig.Metrics.Mode, "pull")
	require.Equal(newConfig.Metrics.Address, "0.0.0.0:9101")
	require.Equal(newConfig.Metrics.JobName, "node-mainnet")
	require.Equal(newConfig.Metrics.Interval, 10*time.Second)
	require.Equal(newConfig.Metrics.Labels["instance"], "asdf-instance-0")
}

func TestConfigMigrationKM(t *testing.T) {
	require := require.New(t)
	newConfig := prepareTest(require, testKMConfigRaw)

	// Now check if the config struct fields actually match the original state.
	require.Equal(newConfig.Mode, config.ModeKeyManager)
	require.Equal(newConfig.Common.DataDir, "/km/data")
	require.Equal(newConfig.Common.Log.Format, "JSON")
	require.Equal(newConfig.Common.Log.Level["default"], "debug")
	require.Equal(newConfig.Genesis.File, "/km/etc/genesis.json")
	require.Equal(newConfig.P2P.Port, uint16(1234))
	require.Equal(newConfig.P2P.Seeds[0], "INSERT_P2P_PUBKEY_HERE@1.2.3.4:26656")
	require.Equal(newConfig.P2P.Seeds[1], "INSERT_P2P_PUBKEY_HERE@1.2.3.4:9200")
	require.Equal(newConfig.P2P.Registration.Addresses[0], "4.3.2.1:26656")
	require.Equal(newConfig.Registration.Entity, "/km/etc/entity/entity.json")
	require.Equal(newConfig.IAS.ProxyAddresses, []string{"foo@1.2.3.4:5678"})
	require.Equal(newConfig.Runtime.Environment, rtConfig.RuntimeEnvironmentSGX)
	require.Equal(newConfig.Runtime.Provisioner, rtConfig.RuntimeProvisionerSandboxed)
	require.Equal(newConfig.Runtime.SGXLoader, "/km/bin/oasis-core-runtime-loader")
	require.Equal(newConfig.Runtime.Paths[0], "/km/runtimes/keymanager.orc")
	require.Equal(newConfig.Consensus.ListenAddress, "tcp://0.0.0.0:26656")
	require.Equal(newConfig.Consensus.ExternalAddress, "tcp://4.3.2.1:26656")
	require.Equal(newConfig.Consensus.Validator, false)
}

func TestConfigMigrationValidator(t *testing.T) {
	require := require.New(t)
	newConfig := prepareTest(require, testValidatorConfigRaw)

	// Now check if the config struct fields actually match the original state.
	require.Equal(newConfig.Mode, config.ModeValidator)
	require.Equal(newConfig.Common.DataDir, "/node/data")
	require.Equal(newConfig.Common.Log.Format, "JSON")
	require.Equal(newConfig.Common.Log.Level["default"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft/context"], "error")
	require.Equal(newConfig.Genesis.File, "/node/etc/genesis.json")
	require.Equal(newConfig.P2P.Seeds[0], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:26656")
	require.Equal(newConfig.P2P.Seeds[1], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:9200")
	require.Equal(newConfig.Consensus.Validator, false)
}

func TestConfigMigrationValidator2(t *testing.T) {
	require := require.New(t)
	newConfig := prepareTest(require, testValidatorConfig2Raw)

	// Now check if the config struct fields actually match the original state.
	require.Equal(newConfig.Mode, config.ModeValidator)
	require.Equal(newConfig.Common.DataDir, "/node/data")
	require.Equal(newConfig.Common.Log.Format, "JSON")
	require.Equal(newConfig.Common.Log.Level["default"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft/context"], "error")
	require.Equal(newConfig.Genesis.File, "/node/etc/genesis.json")
	require.Equal(newConfig.P2P.Seeds[0], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:26656")
	require.Equal(newConfig.P2P.Seeds[1], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:9200")
	require.Equal(newConfig.Consensus.Validator, false)
	require.Equal(newConfig.Consensus.ExternalAddress, "tcp://4.3.2.1:26656")
	require.Equal(newConfig.P2P.Port, uint16(9200))
	require.Equal(len(newConfig.P2P.Registration.Addresses), 1)
	require.Equal(newConfig.P2P.Registration.Addresses[0], "4.3.2.1:9200")
}

func TestConfigMigrationDocsNonValidator(t *testing.T) {
	require := require.New(t)
	newConfig := prepareTest(require, testDocsNonValidatorConfigRaw)

	// Now check if the config struct fields actually match the original state.
	require.Equal(newConfig.Mode, config.ModeClient)
	require.Equal(newConfig.Common.DataDir, "/node/data")
	require.Equal(newConfig.Common.Log.Format, "JSON")
	require.Equal(newConfig.Common.Log.Level["default"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft/context"], "error")
	require.Equal(newConfig.Genesis.File, "/node/etc/genesis.json")
	require.Equal(newConfig.P2P.Seeds[0], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:26656")
	require.Equal(newConfig.P2P.Seeds[1], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:9200")
	require.Equal(newConfig.Consensus.Validator, false)
}

func TestConfigMigrationDocsSeed(t *testing.T) {
	require := require.New(t)
	newConfig := prepareTest(require, testDocsSeedConfigRaw)

	// Now check if the config struct fields actually match the original state.
	require.Equal(newConfig.Mode, config.ModeSeed)
	require.Equal(newConfig.Common.DataDir, "/node/data")
	require.Equal(newConfig.Common.Log.Format, "JSON")
	require.Equal(newConfig.Common.Log.Level["default"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft/context"], "error")
	require.Equal(newConfig.Genesis.File, "/node/etc/genesis.json")
	require.Equal(newConfig.Consensus.Validator, false)
}

func TestConfigMigrationDocsArchive(t *testing.T) {
	require := require.New(t)
	newConfig := prepareTest(require, testDocsArchiveConfigRaw)

	// Now check if the config struct fields actually match the original state.
	require.Equal(newConfig.Mode, config.ModeArchive)
	require.Equal(newConfig.Common.DataDir, "/node/data")
	require.Equal(newConfig.Common.Log.Format, "JSON")
	require.Equal(newConfig.Common.Log.Level["default"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft/context"], "error")
	require.Equal(newConfig.Genesis.File, "/node/etc/genesis.json")
	require.Equal(newConfig.Consensus.Validator, false)
}

func TestConfigMigrationDocsParaTime(t *testing.T) {
	require := require.New(t)
	newConfig := prepareTest(require, testDocsParaTimeConfigRaw)

	// Now check if the config struct fields actually match the original state.
	require.Equal(newConfig.Mode, config.ModeCompute)
	require.Equal(newConfig.Common.DataDir, "/node/data")
	require.Equal(newConfig.Common.Log.Format, "JSON")
	require.Equal(newConfig.Common.Log.Level["default"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft/context"], "error")
	require.Equal(newConfig.Genesis.File, "/node/etc/genesis.json")
	require.Equal(newConfig.P2P.Port, uint16(30002))
	require.Equal(newConfig.P2P.Registration.Addresses[0], "1.2.3.4:30002")
	require.Equal(newConfig.P2P.Seeds[0], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:26656")
	require.Equal(newConfig.P2P.Seeds[1], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:9200")
	require.Equal(newConfig.Registration.Entity, "/node/entity/entity.json")
	require.Equal(newConfig.IAS.ProxyAddresses, []string{"asdf@5.4.3.2:1234"})
	require.Equal(newConfig.Runtime.SGXLoader, "/node/bin/oasis-core-runtime-loader")
	require.Equal(newConfig.Runtime.Paths[0], "/node/runtimes/test.orc")
	require.Equal(newConfig.Consensus.ListenAddress, "tcp://0.0.0.0:26656")
	require.Equal(newConfig.Consensus.ExternalAddress, "tcp://1.2.3.4:26656")
	require.Equal(newConfig.Consensus.Validator, false)
}

func TestConfigMigrationDocsParaTimeClient(t *testing.T) {
	require := require.New(t)
	newConfig := prepareTest(require, testDocsParaTimeClientConfigRaw)

	// Now check if the config struct fields actually match the original state.
	require.Equal(newConfig.Mode, config.ModeClient)
	require.Equal(newConfig.Common.DataDir, "/node/data")
	require.Equal(newConfig.Common.Log.Format, "JSON")
	require.Equal(newConfig.Common.Log.Level["default"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft"], "info")
	require.Equal(newConfig.Common.Log.Level["cometbft/context"], "error")
	require.Equal(newConfig.Genesis.File, "/node/etc/genesis.json")
	require.Equal(newConfig.P2P.Seeds[0], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:26656")
	require.Equal(newConfig.P2P.Seeds[1], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:9200")
	require.Equal(newConfig.Runtime.Paths[0], "/node/runtimes/test.orc")
}

func TestConfigMigrationDocsSentry(t *testing.T) {
	require := require.New(t)
	newConfig := prepareTest(require, testDocsSentryConfigRaw)

	// Now check if the config struct fields actually match the original state.
	require.Equal(newConfig.Mode, config.ModeClient)
	require.Equal(newConfig.Common.DataDir, "/serverdir/node")
	require.Equal(newConfig.Common.Log.Format, "JSON")
	require.Equal(newConfig.Common.Log.Level["default"], "debug")
	require.Equal(newConfig.Common.Log.Level["cometbft"], "warn")
	require.Equal(newConfig.Common.Log.Level["cometbft/context"], "error")
	require.Equal(newConfig.Genesis.File, "/serverdir/etc/genesis.json")
	require.Equal(newConfig.Consensus.ListenAddress, "tcp://0.0.0.0:26656")
	require.Equal(newConfig.Consensus.ExternalAddress, "tcp://6.7.8.9:26656")
	require.Equal(newConfig.Consensus.Prune.Strategy, "keep_n")
	require.Equal(newConfig.Consensus.Prune.NumKept, uint64(600))
	require.Equal(newConfig.Sentry.Enabled, true)
	require.Equal(newConfig.Sentry.Control.Port, uint16(9009))
	require.Equal(newConfig.Sentry.Control.AuthorizedPubkeys[0], "asdf")
	require.Equal(newConfig.P2P.Seeds[0], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:26656")
	require.Equal(newConfig.P2P.Seeds[1], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:9200")
	require.Equal(newConfig.Consensus.SentryUpstreamAddresses[0], "INSERT_P2P_PUBKEY_HERE@1.2.3.4:26656")
}

func TestConfigMigrationSocketOverride(t *testing.T) {
	require := require.New(t)
	newConfig := prepareTest(require, testInternalSocketOverrideConfigRaw)

	// Now check if the config struct fields actually match the original state.
	require.Equal(newConfig.Mode, config.ModeClient)
	require.Equal(newConfig.Common.DataDir, "/node/data")
	require.Equal(newConfig.Common.Log.Format, "JSON")
	require.Equal(newConfig.Common.Log.Level["default"], "debug")
	require.Equal(newConfig.Common.Log.Level["cometbft"], "debug")
	require.Equal(newConfig.Common.Log.Level["cometbft/context"], "error")
	require.Equal(newConfig.Genesis.File, "/node/etc/genesis.json")
	require.Equal(newConfig.P2P.Seeds[0], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:26656")
	require.Equal(newConfig.P2P.Seeds[1], "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:9200")
	require.Equal(newConfig.Runtime.Paths[0], "/node/runtime/cipher-paratime-2.6.2.orc")
	require.Equal(newConfig.Runtime.Paths[1], "/node/runtime/emerald-paratime-10.0.0.orc")
	require.Equal(newConfig.Runtime.Paths[2], "/node/runtime/sapphire-paratime-0.4.0.orc")
	require.Equal(newConfig.Storage.Checkpointer.Enabled, true)
	require.Equal(newConfig.Common.InternalSocketPath, "/node/custom-internal.sock")
}
