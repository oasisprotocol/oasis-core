// Package migrate implements the migrate command.
// nolint: gocyclo,revive,govet,goconst
package migrate

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/config"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
)

const (
	cfgIn  = "in"
	cfgOut = "out"
)

var (
	migrateCmd = &cobra.Command{
		Use:   "migrate",
		Short: "migrate YAML config file into new format",
		Run:   doMigrateConfig,
	}

	migrateFlags = flag.NewFlagSet("", flag.ContinueOnError)

	logger = logging.GetLogger("cmd/config/migrate")

	// This is a bit of a kludge to allow running the command from unit tests
	// multiple times without getting a "logging: already initialized" error.
	initOnce sync.Once
)

// Recursively prune maps that are empty.
func pruneEmptyMaps(m map[string]interface{}) {
	for k, v := range m {
		if vMap, isMap := v.(map[string]interface{}); isMap {
			pruneEmptyMaps(vMap)
			if len(vMap) == 0 {
				delete(m, k)
			}
		}
	}
}

// Translate known P2P addresses from the old format into the new.
func translateKnownP2P(in []string) ([]string, uint) {
	// Old format is the Tendermint P2P address, which we can't translate
	// automatically because it is hashed.
	// New format is the node's P2P public key.
	// However, we know both the old and new addresses of Oasis public
	// seed nodes for the testnet and mainnet, so we can at least translate
	// those.

	known := map[string]string{
		// Mainnet seed node.
		"E27F6B7A350B4CC2B48A6CBE94B0A02B0DCB0BF3@35.199.49.168:26656": "H6u9MtuoWRKn5DKSgarj/dzr2Z9BsjuRHgRAoXITOcU=@35.199.49.168:26656",
		// Testnet seed node.
		"53572F689E5BACDD3C6527E6594EC49C8F3093F6@34.86.165.6:26656": "HcDFrTp/MqRHtju5bCx6TIhIMd6X/0ZQ3lUG73q5898=@34.86.165.6:26656",
	}

	var numUnknown uint

	out := []string{}
	for _, p2pOld := range in {
		var p2pNew string

		if knownNew, isKnown := known[p2pOld]; isKnown {
			// New address is known, use it.
			p2pNew = knownNew
		} else {
			// New address is not known, make sure the user replaces the ID.
			s := strings.Split(p2pOld, "@")
			addr := s[len(s)-1]
			p2pNew = fmt.Sprintf("INSERT_P2P_PUBKEY_HERE@%s", addr)
			numUnknown++
		}

		out = append(out, p2pNew)
	}

	return out, numUnknown
}

// Wrapper for the above function that simplifies logging.
func convertP2P(i interface{}, oldS string, newS string) []string {
	if i == nil {
		return []string{}
	}

	// Go can't convert interface{} into []string in one go, so we have to
	// do it in two steps.
	in1, ok := i.([]interface{})
	if !ok {
		logger.Error("P2P address list in input file is malformed", "section", oldS, "expected", "[]interface{}", "got", fmt.Sprintf("%T", i))
		os.Exit(1)
	}

	if len(in1) == 0 {
		return []string{}
	}

	in := make([]string, len(in1))
	for idx, ii := range in1 {
		if s, ok := ii.(string); ok {
			in[idx] = s
		} else {
			logger.Error("P2P address list in input file is malformed", "section", oldS, "expected", "string", "got", fmt.Sprintf("%T", ii))
			os.Exit(1)
		}
	}

	out, numUnknown := translateKnownP2P(in)

	if numUnknown == uint(len(in)) {
		logger.Error(fmt.Sprintf("%s is now %s, but instead of Tendermint P2P addresses we now use P2P public keys here, so manual migration of all addresses is required -- replace INSERT_P2P_PUBKEY_HERE with the P2P public key of the node (use 'oasis-node control status' to get its P2P public key)", oldS, newS))
	} else if numUnknown > 0 {
		logger.Error(fmt.Sprintf("%s is now %s, but instead of Tendermint P2P addresses we now use P2P public keys here, so manual migration of some addresses is required -- replace INSERT_P2P_PUBKEY_HERE with the P2P public key of the node (use 'oasis-node control status' to get its P2P public key)", oldS, newS))
	} else {
		logger.Warn(fmt.Sprintf("%s is now %s, but instead of Tendermint P2P addresses we now use P2P public keys here, however, all the addresses in this section of your config file have known translation mappings and were automatically translated for you", oldS, newS))
	}

	return out
}

// AppendLibp2pAddrs appends the corresponding libp2p seed node address (which
// differs only in the port number) for each Tendermint seed node address.
func appendLibp2pAddrs(in []string) []string {
	out := []string{}
	for _, addr := range in {
		out = append(out, addr)

		idxOfColon := strings.Index(addr, ":")
		if idxOfColon != -1 {
			entry := addr[0:idxOfColon]
			p2pRT := entry + ":9200"
			out = append(out, p2pRT)
		}
	}
	return out
}

func doMigrateConfig(cmd *cobra.Command, args []string) {
	initOnce.Do(func() {
		config.GlobalConfig.Common.Log.Level["default"] = "info"
		if err := cmdCommon.Init(); err != nil {
			cmdCommon.EarlyLogAndExit(err)
		}
	})

	// Perform some sanity checks on the input and output file names.
	cfgInFileName := viper.GetString(cfgIn)
	cfgOutFileName := viper.GetString(cfgOut)

	if len(cfgInFileName) == 0 {
		logger.Error("input file name missing, use the --in flag to specify it")
		os.Exit(1)
	}
	if len(cfgOutFileName) == 0 {
		logger.Error("output file name missing, use the --out flag to specify it")
		os.Exit(1)
	}
	if cfgInFileName == cfgOutFileName {
		logger.Error("input and output file names must be different")
		os.Exit(1)
	}

	// Start with a blank config that we will populate as we convert the old one.
	//
	// NOTE: We don't use config.DefaultConfig() here on purpose, since the
	// input config file might contain some environment variable substitutions
	// and would fail to parse as the appropriate type from the structs when
	// saving it later.
	// Additionally, we don't want to write any settings that weren't also
	// present in the old config file to keep the new config file pretty.
	newCfg := make(map[string]interface{})

	logger.Info("loading input config file", "file_name", cfgInFileName)

	// Load input config file.
	oldCfgRaw, err := os.ReadFile(cfgInFileName)
	if err != nil {
		logger.Error("failed to read input file", "file_name", cfgInFileName, "err", err)
		os.Exit(1)
	}

	// Parse old config into map.
	oldCfg := make(map[string]interface{})
	err = yaml.Unmarshal(oldCfgRaw, &oldCfg)
	if err != nil {
		logger.Error("failed to parse input file", "file_name", cfgInFileName, "err", err)
		os.Exit(1)
	}

	logger.Info("input config file loaded successfully", "file_name", cfgInFileName)

	// Helper for making sub-maps.
	mkSubMap := func(root map[string]interface{}, name string) {
		if _, ok := root[name]; !ok {
			root[name] = make(map[string]interface{})
		}
	}

	// Helper for casting into maps (we're going to be doing that a lot).
	m := func(i interface{}) map[string]interface{} {
		if i == nil {
			return make(map[string]interface{})
		}

		ret, ok := i.(map[string]interface{})
		if !ok {
			var from string
			_, file, line, ok := runtime.Caller(1)
			if ok {
				from = fmt.Sprintf("%s:%d", file, line)
			} else {
				from = "unknown"
			}
			logger.Error("invalid input file format", "from", from)
			os.Exit(1)
		}
		return ret
	}

	// Convert known keys into new format section by section...
	logger.Info("config file migration has started")

	nodeMode := "client"
	consensus, ok := oldCfg["consensus"]
	if ok {
		if validator, ok := m(consensus)["validator"]; ok {
			mkSubMap(newCfg, "consensus")
			m(newCfg["consensus"])["validator"] = validator
			delete(m(consensus), "validator")
		}

		if tendermint, ok := m(consensus)["tendermint"]; ok {
			if mode, ok := m(tendermint)["mode"]; ok {
				logger.Warn("consensus.tendermint.mode has been deprecated in favor of using the global node mode")
				if mode == "archive" {
					logger.Warn("node mode set to archive")
					nodeMode = "archive"
				} else if mode == "seed" {
					logger.Warn("node mode set to seed")
					nodeMode = "seed"
				}
				delete(m(tendermint), "mode")
			}

			if len(m(tendermint)) > 0 {
				logger.Info("consensus.tendermint.* is now consensus.*")
				mkSubMap(newCfg, "consensus")
				for k, v := range m(tendermint) {
					if k == "core" {
						if la, ok := m(v)["listen_address"]; ok {
							logger.Info("consensus.tendermint.core.listen_address is now consensus.listen_address")
							m(newCfg["consensus"])["listen_address"] = la
							delete(m(m(tendermint)["core"]), "listen_address")
						}
						if ea, ok := m(v)["external_address"]; ok {
							logger.Info("consensus.tendermint.core.external_address is now consensus.external_address")
							m(newCfg["consensus"])["external_address"] = ea
							delete(m(m(tendermint)["core"]), "external_address")
						}
					} else if k == "log" {
						if dbg, ok := m(v)["debug"]; ok {
							logger.Info("consensus.tendermint.log.debug is now consensus.log_debug")
							m(newCfg["consensus"])["log_debug"] = dbg
							delete(m(m(tendermint)["log"]), "debug")
						}
					} else if k == "light_client" {
						if tp, ok := m(v)["trust_period"]; ok {
							logger.Info("consensus.tendermint.light_client.trust_period is now consensus.state_sync.trust_period")
							mkSubMap(m(newCfg["consensus"]), "state_sync")
							m(m(newCfg["consensus"])["state_sync"])["trust_period"] = tp
							delete(m(m(tendermint)["light_client"]), "trust_period")
						}
					} else if k == "seed" {
						if dbg, ok := m(v)["debug"]; ok {
							if dabfg, ok := m(dbg)["disable_addr_book_from_genesis"]; ok {
								logger.Info("consensus.tendermint.seed.debug.disable_addr_book_from_genesis is now consensus.debug.disable_addr_book_from_genesis")
								mkSubMap(m(newCfg["consensus"]), "debug")
								m(m(newCfg["consensus"])["debug"])["disable_addr_book_from_genesis"] = dabfg
								delete(m(m(m(tendermint)["seed"])["debug"]), "disable_addr_book_from_genesis")
							}
						}
					} else if k == "state_sync" {
						if _, ok = m(v)["consensus_node"]; ok {
							logger.Info("consensus.state_sync.consensus_node is no longer needed")
							delete(m(v), "consensus_node")
						}
						m(newCfg["consensus"])["state_sync"] = v
						delete(m(tendermint), "state_sync")
					} else if k == "sentry" {
						if upaddr, ok := m(v)["upstream_address"]; ok {
							m(newCfg["consensus"])["sentry_upstream_addresses"] = convertP2P(upaddr, "consensus.tendermint.sentry.upstream_address", "consensus.sentry_upstream_addresses")
							delete(m(m(tendermint)["sentry"]), "upstream_address")
						}
					} else if k == "upgrade" {
						if sd, ok := m(v)["stop_delay"]; ok {
							logger.Info("consensus.tendermint.upgrade.stop_delay is now consensus.upgrade_stop_delay")
							m(newCfg["consensus"])["upgrade_stop_delay"] = sd
							delete(m(m(tendermint)["upgrade"]), "stop_delay")
						}
					} else if k == "supplementarysanity" {
						logger.Info("consensus.tendermint.supplementarysanity.* is now consensus.supplementary_sanity.*")
						m(newCfg["consensus"])["supplementary_sanity"] = v
						delete(m(tendermint), k)
					} else if k == "p2p" {
						mkSubMap(m(newCfg["consensus"]), "p2p")
						for pk, pv := range m(v) {
							if pk == "persistent_peer" {
								m(m(newCfg["consensus"])["p2p"])["persistent_peers"] = convertP2P(pv, "consensus.tendermint.p2p.persistent_peer", "consensus.p2p.persistent_peers")
								delete(m(m(tendermint)["p2p"]), pk)
								continue
							} else if pk == "unconditional_peer" || pk == "unconditional_peer_ids" {
								m(m(newCfg["consensus"])["p2p"])["unconditional_peers"] = convertP2P(pv, fmt.Sprintf("consensus.tendermint.p2p.%s", pk), "consensus.p2p.unconditional_peers")
								delete(m(m(tendermint)["p2p"]), pk)
								continue
							} else if pk == "seed" {
								mkSubMap(newCfg, "p2p")
								m(newCfg["p2p"])["seeds"] = appendLibp2pAddrs(convertP2P(pv, "consensus.tendermint.p2p.seed", "p2p.seeds"))
								delete(m(m(tendermint)["p2p"]), pk)
								continue
							}
							m(m(newCfg["consensus"])["p2p"])[pk] = pv
							delete(m(m(tendermint)["p2p"]), pk)
						}
					} else if k == "abci" {
						if prune, ok := m(v)["prune"]; ok {
							logger.Info("consensus.tendermint.abci.prune.* is now consensus.prune.*")
							m(newCfg["consensus"])["prune"] = prune
							delete(m(m(tendermint)["abci"]), "prune")
						}
					} else {
						m(newCfg["consensus"])[k] = v
						delete(m(tendermint), k)
					}
				}
			}
		}
	}

	runtime, ok := oldCfg["runtime"]
	if ok {
		if mode, ok := m(runtime)["mode"]; ok {
			logger.Warn("runtime.mode has been deprecated in favor of using the global node mode")
			if modeStr, ok := mode.(string); ok {
				if modeStr != "none" && modeStr != nodeMode {
					nodeMode = modeStr
					logger.Warn("node mode set to runtime.mode", "mode", nodeMode)
				}
				delete(m(runtime), "mode")
			} else {
				logger.Error("runtime.mode has invalid type (string expected)")
			}
		}

		if sandbox, ok := m(runtime)["sandbox"]; ok {
			if binary, ok := m(sandbox)["binary"]; ok {
				logger.Info("runtime.sandbox.binary is now runtime.sandbox_binary")
				mkSubMap(newCfg, "runtime")
				m(newCfg["runtime"])["sandbox_binary"] = binary
				delete(m(sandbox), "binary")
			} else {
				logger.Warn("input has invalid entries under runtime.sandbox")
			}
		}

		if sgx, ok := m(runtime)["sgx"]; ok {
			if loader, ok := m(sgx)["loader"]; ok {
				logger.Info("runtime.sgx.loader is now runtime.sgx_loader")
				mkSubMap(newCfg, "runtime")
				m(newCfg["runtime"])["sgx_loader"] = loader
				delete(m(sgx), "loader")
			} else {
				logger.Warn("input has invalid entries under runtime.sgx")
			}
		}

		if history, ok := m(runtime)["history"]; ok {
			if pruner, ok := m(history)["pruner"]; ok {
				logger.Info("runtime.history.pruner is now runtime.prune")
				mkSubMap(newCfg, "runtime")
				m(newCfg["runtime"])["prune"] = m(pruner)
				delete(m(history), "pruner")
			} else {
				logger.Warn("input has invalid entries under runtime.history")
			}
		}

		if provisioner, ok := m(runtime)["provisioner"]; ok {
			mkSubMap(newCfg, "runtime")
			m(newCfg["runtime"])["provisioner"] = provisioner
			delete(m(runtime), "provisioner")
		}

		if paths, ok := m(runtime)["paths"]; ok {
			mkSubMap(newCfg, "runtime")
			m(newCfg["runtime"])["paths"] = paths
			delete(m(runtime), "paths")
		}

		if environment, ok := m(runtime)["environment"]; ok {
			mkSubMap(newCfg, "runtime")
			m(newCfg["runtime"])["environment"] = environment
			delete(m(runtime), "environment")
		}

		if cfg, ok := m(runtime)["config"]; ok {
			mkSubMap(newCfg, "config")
			m(newCfg["runtime"])["config"] = cfg
			delete(m(runtime), "config")
		}
	}

	worker, ok := oldCfg["worker"]
	if ok {
		if client, ok := m(worker)["client"]; ok {
			if _, ok := m(client)["port"]; ok {
				logger.Warn("worker.client.port has been deprecated as it is no longer required")
				delete(m(client), "port")
			}
		}

		if registration, ok := m(worker)["registration"]; ok {
			if _, ok := m(registration)["force_register"]; ok {
				logger.Warn("worker.registration.force_register has been deprecated, use the 'oasis-node control clear-deregister' command instead")
				delete(m(registration), "force_register")
			}

			// Copy the remaining keys.
			if len(m(registration)) > 0 {
				logger.Info("worker.registration.* is now registration.*")
				mkSubMap(newCfg, "registration")
				for k, v := range m(registration) {
					m(newCfg["registration"])[k] = v
					delete(m(registration), k)
				}
			}
		}

		if tx_pool, ok := m(worker)["tx_pool"]; ok {
			logger.Info("worker.tx_pool.* is now runtime.tx_pool.*")
			mkSubMap(newCfg, "runtime")
			mkSubMap(m(newCfg["runtime"]), "tx_pool")
			for k, v := range m(tx_pool) {
				m(m(newCfg["runtime"])["tx_pool"])[k] = v
				delete(m(tx_pool), k)
			}
		}

		if sentry, ok := m(worker)["sentry"]; ok {
			logger.Info("worker.sentry.* is now sentry.*")
			mkSubMap(newCfg, "sentry")
			for k, v := range m(sentry) {
				if k == "addresses" {
					logger.Info("worker.sentry.addresses is now runtime.sentry_addresses")
					mkSubMap(newCfg, "runtime")
					m(newCfg["runtime"])["sentry_addresses"] = v
					delete(m(sentry), "addresses")
				} else if k == "control" {
					mkSubMap(m(newCfg["sentry"]), "control")
					if port, ok := m(v)["port"]; ok {
						m(m(newCfg["sentry"])["control"])["port"] = port
					}
					if ap, ok := m(v)["authorized_pubkey"]; ok {
						logger.Info("worker.sentry.control.authorized_pubkey is now sentry.control.authorized_pubkeys")
						m(m(newCfg["sentry"])["control"])["authorized_pubkeys"] = ap
					}
					delete(m(sentry), "control")
				} else {
					m(newCfg["sentry"])[k] = v
					delete(m(sentry), k)
				}
			}
		}

		if keymanager, ok := m(worker)["keymanager"]; ok {
			logger.Info("worker.keymanager.* is now keymanager.*")
			mkSubMap(newCfg, "keymanager")
			for k, v := range m(keymanager) {
				if k == "runtime" {
					if id, ok := m(v)["id"]; ok {
						logger.Info("worker.keymanager.runtime.id is now keymanager.runtime_id")
						m(newCfg["keymanager"])["runtime_id"] = id
						delete(m(m(keymanager)["runtime"]), "id")
					} else {
						logger.Warn("worker.keymanager.runtime is malformed (missing 'id' field)")
					}
				} else {
					m(newCfg["keymanager"])[k] = v
					delete(m(keymanager), k)
				}
			}
		}

		if storage, ok := m(worker)["storage"]; ok {
			logger.Info("worker.storage.* is now storage.*")
			mkSubMap(newCfg, "storage")
			for k, v := range m(storage) {
				if k == "public_rpc" {
					if enabled, ok := m(v)["enabled"]; ok {
						logger.Info("worker.storage.public_rpc.enabled is now storage.public_rpc_enabled")
						m(newCfg["storage"])["public_rpc_enabled"] = enabled
						delete(m(m(storage)["public_rpc"]), "enabled")
					} else {
						logger.Warn("worker.storage.public_rpc is malformed (missing 'enabled' field)")
					}
				} else if k == "checkpoint_sync" {
					if disabled, ok := m(v)["disabled"]; ok {
						logger.Info("worker.storage.checkpoint_sync.disabled is now storage.checkpoint_sync_disabled")
						m(newCfg["storage"])["checkpoint_sync_disabled"] = disabled
						delete(m(m(storage)["checkpoint_sync"]), "disabled")
					} else {
						logger.Warn("worker.storage.checkpoint_sync is malformed (missing 'disabled' field)")
					}
				} else {
					m(newCfg["storage"])[k] = v
					delete(m(storage), k)
				}
			}
		}

		if p2p, ok := m(worker)["p2p"]; ok {
			if port, ok := m(p2p)["port"]; ok {
				logger.Info("worker.p2p.port is now p2p.port")
				mkSubMap(newCfg, "p2p")
				m(newCfg["p2p"])["port"] = port
				delete(m(p2p), "port")
			}

			if addresses, ok := m(p2p)["addresses"]; ok {
				logger.Info("worker.p2p.addresses is now p2p.registration.addresses")
				mkSubMap(newCfg, "p2p")
				mkSubMap(m(newCfg["p2p"]), "registration")
				m(m(newCfg["p2p"])["registration"])["addresses"] = addresses
				delete(m(p2p), "addresses")
			}

			// Migrate gossipsub config.
			for _, k := range []string{
				"peer_outbound_queue_size",
				"validate_queue_size",
				"validate_concurrency",
				"validate_throttle",
			} {
				if v, ok := m(p2p)[k]; ok {
					logger.Info(fmt.Sprintf("worker.p2p.%s is now p2p.gossipsub.%s", k, k))
					mkSubMap(newCfg, "p2p")
					mkSubMap(m(newCfg["p2p"]), "gossipsub")
					m(m(newCfg["p2p"])["gossipsub"])[k] = v
					delete(m(p2p), k)
				}
			}

			// Migrate connection manager config.
			for _, k := range []string{
				"max_num_peers",
				"peer_grace_period",
				"persistent_peers",
			} {
				if v, ok := m(p2p)[k]; ok {
					logger.Info(fmt.Sprintf("worker.p2p.%s is now p2p.connection_manager.%s", k, k))
					mkSubMap(newCfg, "p2p")
					mkSubMap(m(newCfg["p2p"]), "connection_manager")
					m(m(newCfg["p2p"])["connection_manager"])[k] = v
					delete(m(p2p), k)
				}
			}

			if blocked_peers, ok := m(p2p)["blocked_peers"]; ok {
				logger.Info("worker.p2p.blocked_peers is now p2p.connection_gater.blocked_peers")
				mkSubMap(newCfg, "p2p")
				mkSubMap(m(newCfg["p2p"]), "connection_gater")
				m(m(newCfg["p2p"])["connection_gater"])["blocked_peers"] = blocked_peers
				delete(m(p2p), "blocked_peers")
			}

			if connectedness_low_water, ok := m(p2p)["connectedness_low_water"]; ok {
				logger.Info("worker.p2p.connectedness_low_water is now p2p.peer_manager.connectedness_low_water")
				mkSubMap(newCfg, "p2p")
				mkSubMap(m(newCfg["p2p"]), "peer_manager")
				m(m(newCfg["p2p"])["peer_manager"])["connectedness_low_water"] = connectedness_low_water
				delete(m(p2p), "connectedness_low_water")
			}
		}
	}

	datadir, ok := oldCfg["datadir"]
	if ok {
		logger.Info("datadir is now common.data_dir")
		mkSubMap(newCfg, "common")
		m(newCfg["common"])["data_dir"] = datadir
		delete(oldCfg, "datadir")
	}

	log, ok := oldCfg["log"]
	if ok {
		logger.Info("log.* is now common.log.*")
		mkSubMap(newCfg, "common")
		mkSubMap(m(newCfg["common"]), "log")
		mLog := m(m(newCfg["common"])["log"])

		if file, ok := m(log)["file"]; ok {
			mLog["file"] = file
			delete(m(log), "file")
		}

		if format, ok := m(log)["format"]; ok {
			mLog["format"] = format
			delete(m(log), "format")
		}

		if level, ok := m(log)["level"]; ok {
			if mLevel, isMap := level.(map[string]interface{}); isMap {
				// Copy the map.
				mkSubMap(mLog, "level")
				for k, v := range mLevel {
					// Also replace any occurrences of 'tendermint' with
					// 'cometbft' in the keys.
					newK := strings.Replace(k, "tendermint", "cometbft", -1)
					m(mLog["level"])[newK] = v
				}
			} else {
				if sLevel, isString := level.(string); isString {
					// If only a single level is given instead of the map,
					// convert it into a map with only the default level.
					mkSubMap(mLog, "level")
					m(mLog["level"])["default"] = sLevel
				} else {
					logger.Warn("log.level is malformed, ignoring")
				}
			}
			delete(m(log), "level")
		}
	}

	debug, ok := oldCfg["debug"]
	if ok {
		logger.Info("debug.* is now common.debug.*")
		mkSubMap(newCfg, "common")
		mkSubMap(m(newCfg["common"]), "debug")
		mDebug := m(m(newCfg["common"])["debug"])

		if rlimit, ok := m(debug)["rlimit"]; ok {
			mDebug["rlimit"] = rlimit
			delete(m(debug), "rlimit")
		}

		if allow_root, ok := m(debug)["allow_root"]; ok {
			mDebug["allow_root"] = allow_root
			delete(m(debug), "allow_root")
		}
	}

	pprof, ok := oldCfg["pprof"]
	if ok {
		if bind, ok := m(pprof)["bind"]; ok {
			logger.Info("pprof.bind is now pprof.bind_address")
			mkSubMap(newCfg, "pprof")
			m(newCfg["pprof"])["bind_address"] = bind
			delete(m(pprof), "bind")
		}
	}

	ias, ok := oldCfg["ias"]
	if ok {
		mkSubMap(newCfg, "ias")
		mIAS := m(newCfg["ias"])

		if proxy, ok := m(ias)["proxy"]; ok {
			if address, ok := m(proxy)["address"]; ok {
				logger.Info("ias.proxy.address is now ias.proxy_address")
				mIAS["proxy_address"] = address
				delete(m(proxy), "address")
			}
		}

		if debug, ok := m(ias)["debug"]; ok {
			if skip_verify, ok := m(debug)["skip_verify"]; ok {
				logger.Info("ias.debug.skip_verify is now ias.debug_skip_verify")
				mIAS["debug_skip_verify"] = skip_verify
				delete(m(debug), "skip_verify")
			}
		}
	}

	genesis, ok := oldCfg["genesis"]
	if ok {
		mkSubMap(newCfg, "genesis")
		mGen := m(newCfg["genesis"])

		if file, ok := m(genesis)["file"]; ok {
			mGen["file"] = file
			delete(m(genesis), "file")
		}
	}

	metrics, ok := oldCfg["metrics"]
	if ok {
		mkSubMap(newCfg, "metrics")
		newCfg["metrics"] = metrics
		delete(oldCfg, "metrics")
	}

	// If we deleted any keys, make sure we don't retain empty structures.
	pruneEmptyMaps(oldCfg)
	// Also prune new config.
	pruneEmptyMaps(newCfg)

	// Check for options that are only available on the command-line.
	if _, ok = oldCfg["debug"]; ok {
		logger.Warn("note that some debug.* options are from now on only available on the command-line")
	}
	if _, ok = oldCfg["grpc"]; ok {
		logger.Warn("note that grpc.* options are from now on only available on the command-line")
	}

	logger.Info("config file migration completed")

	// Print sections remaining in map (if any).
	if len(oldCfg) > 0 {
		remaining, grr := yaml.Marshal(&oldCfg)
		if grr != nil {
			logger.Error("failed to marshal remaining sections from input file", "err", grr)
			os.Exit(1)
		}

		fmt.Printf("Ignored unknown sections from input file, please review manually:\n%s\n", remaining)
	}

	logger.Info("saving migrated config file", "file_name", cfgOutFileName)

	// Save new config to file.
	newCfgRaw, err := yaml.Marshal(&newCfg)
	if err != nil {
		logger.Error("failed to convert migrated config file into YAML", "err", err)
		os.Exit(1)
	}
	// Prepend the node mode at the very beginning.
	newCfgRaw = append([]byte(fmt.Sprintf("mode: %s\n", nodeMode)), newCfgRaw...)
	if err = os.WriteFile(cfgOutFileName, newCfgRaw, 0o600); err != nil {
		logger.Error("failed to write migrated config file", "file_name", cfgOutFileName, "err", err)
		os.Exit(1)
	}

	logger.Info("migrated config file saved successfully", "file_name", cfgOutFileName)

	// Validate new config.
	logger.Info("validating migrated config file")
	newCfgStruct := config.DefaultConfig()
	dec := yaml.NewDecoder(bytes.NewReader(newCfgRaw))
	dec.KnownFields(true)
	err = dec.Decode(&newCfgStruct)
	if err != nil && err != io.EOF {
		logger.Error("failed to parse config file after migration (this might be normal if you're using environment variable substitutions in your original config file)", "err", err)
		os.Exit(1)
	}
	err = newCfgStruct.Validate()
	if err != nil {
		logger.Error("failed to validate migrated config file (this might be normal if you're using environment variable substitutions in your original config file)", "err", err)
		os.Exit(1)
	} else {
		logger.Info("validation of the migrated config file completed successfully")
	}

	logger.Info("migration completed successfully", "new_config_file_name", cfgOutFileName)
}

// Register registers the migrate-config sub-command.
func Register(parentCmd *cobra.Command) {
	migrateCmd.PersistentFlags().AddFlagSet(migrateFlags)
	parentCmd.AddCommand(migrateCmd)
}

func init() {
	migrateFlags.String(cfgIn, "config.yaml", "path to input config file")
	migrateFlags.String(cfgOut, "config_new.yaml", "path to output config file")
	_ = viper.BindPFlags(migrateFlags)
}
