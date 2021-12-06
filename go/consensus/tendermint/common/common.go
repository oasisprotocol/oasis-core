package common

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	tminternal "github.com/tendermint/tendermint/uninternal"

	"github.com/oasisprotocol/oasis-core/go/common"
)

const (
	// StateDir is the name of the directory located inside the node's data
	// directory which contains the tendermint state.
	StateDir = "tendermint"

	// ConfigDir is the name of the Tendermint configuration directory.
	ConfigDir = "config"
)

const (
	// CfgCoreExternalAddress configures the tendermint external address.
	CfgCoreExternalAddress = "consensus.tendermint.core.external_address"

	// CfgCoreListenAddress configures the tendermint core network listen address.
	CfgCoreListenAddress = "consensus.tendermint.core.listen_address"

	// CfgDebugP2PAddrBookLenient configures allowing non-routable addresses.
	CfgDebugP2PAddrBookLenient = "consensus.tendermint.debug.addr_book_lenient"
	// CfgDebugP2PAllowDuplicateIP allows multiple connections from the same IP.
	CfgDebugP2PAllowDuplicateIP = "consensus.tendermint.debug.allow_duplicate_ip"

	// CfgLogDebug configures Tendermint debug logging.
	CfgLogDebug = "consensus.tendermint.log.debug"

	// CfgSubmissionGasPrice configures the gas price used when submitting transactions.
	CfgSubmissionGasPrice = "consensus.tendermint.submission.gas_price"
	// CfgSubmissionMaxFee configures the maximum fee that can be set.
	CfgSubmissionMaxFee = "consensus.tendermint.submission.max_fee"

	// CfgP2PSeed configures tendermint's seed node(s).
	CfgP2PSeed = "consensus.tendermint.p2p.seed"
	// CfgP2PMaxConnections configures the max number of connected peers (inbound and outbound).
	CfgP2PMaxConnections = "consensus.tendermint.p2p.max_connections"
	// CfgP2PMaxPeers configures the max number of peers.
	CfgP2PMaxPeers = "consensus.tendermint.p2p.max_peers"
	// CfgP2PWhitelistedPeers configures the whitelisted peers.
	CfgP2PWhitelistedPeers = "consensus.tendermint.p2p.whitelisted_peers"
	// CfgP2PBlacklistedPeerIPs configures the blacklisted peer IPs.
	CfgP2PBlacklistedPeerIPs = "consensus.tendermint.p2p.blacklisted_peer_ips"
	// CfgP2PSendRate is the rate at which packets can be sent, in bytes/second.
	CfgP2PSendRate = "consensus.tendermint.p2p.send_rate"
	// CfgP2PRecvRate is the rate at which packets can be received, in bytes/second.
	CfgP2PRecvRate = "consensus.tendermint.p2p.recv_rate"
	// CfgP2PSentryPeers automatically sets CfgP2PWhitelistedPeers,
	// CfgP2PMaxPeers, and CfgP2PMaxConnections accordingly.
	// Format is the same as for whitelisted peers.
	CfgP2PSentryPeers = "consensus.tendermint.p2p.sentry_peers"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// GetPeersFromRPCEnvironment returns the node's peers.
func GetPeersFromRPCEnvironment(env *tminternal.RPCEnvironment) []string {
	if env != nil {
		if env.PeerManager != nil {
			p2pPeers := env.PeerManager.Peers()
			if p2pPeers != nil {
				peers := make([]string, 0, len(p2pPeers))
				for _, peer := range p2pPeers {
					addrs := env.PeerManager.Addresses(peer)
					for _, addr := range addrs {
						peers = append(peers, addr.String())
					}
				}
				return peers
			}
		}
	}

	return []string{}
}

// GetExternalAddress returns the configured tendermint external address.
func GetExternalAddress() (*url.URL, error) {
	addrURI := viper.GetString(CfgCoreExternalAddress)
	if addrURI == "" {
		addrURI = viper.GetString(CfgCoreListenAddress)
	}
	if addrURI == "" {
		return nil, fmt.Errorf("tendermint: no external address configured")
	}

	u, err := url.Parse(addrURI)
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to parse external address URL: %w", err)
	}

	if u.Scheme != "tcp" {
		return nil, fmt.Errorf("tendermint: external address has invalid scheme: '%v'", u.Scheme)
	}

	// Handle the case when no IP is explicitly configured, and the
	// default value is used.
	if u.Hostname() == "0.0.0.0" {
		var port string
		if _, port, err = net.SplitHostPort(u.Host); err != nil {
			return nil, fmt.Errorf("tendermint: malformed external address host/port: %w", err)
		}

		ip := common.GuessExternalAddress()
		if ip == nil {
			return nil, fmt.Errorf("tendermint: failed to guess external address")
		}

		u.Host = ip.String() + ":" + port
	}

	return u, nil
}

// InitDataDir initializes the data directory for Tendermint.
func InitDataDir(dataDir string) error {
	subDirs := []string{
		ConfigDir,
		"data", // Required by `tendermint/privval/FilePV.Save()`.
	}

	if err := common.Mkdir(dataDir); err != nil {
		return err
	}

	for _, subDir := range subDirs {
		if err := common.Mkdir(filepath.Join(dataDir, subDir)); err != nil {
			return err
		}
	}

	return nil
}

func init() {
	Flags.String(CfgCoreExternalAddress, "", "tendermint address advertised to other nodes")
	Flags.String(CfgCoreListenAddress, "tcp://0.0.0.0:26656", "tendermint core listen address")
	Flags.Bool(CfgDebugP2PAddrBookLenient, false, "allow non-routable addresses")
	Flags.Bool(CfgDebugP2PAllowDuplicateIP, false, "Allow multiple connections from the same IP")

	Flags.StringSlice(CfgP2PSeed, []string{}, "Tendermint seed node(s) of the form ID@host:port")
	Flags.Uint16(CfgP2PMaxConnections, 120, "Max number of peer connections (inbound and outbound)")
	Flags.Uint16(CfgP2PMaxPeers, 1000, "Max number of peers to keep track of")
	Flags.StringSlice(CfgP2PWhitelistedPeers, []string{}, "Tendermint whitelisted peers")
	Flags.StringSlice(CfgP2PBlacklistedPeerIPs, []string{}, "Tendermint blacklisted peer IPs")
	Flags.StringSlice(CfgP2PSentryPeers, []string{}, "Tendermint sentry peers (automatically adds the sentry peers to whitelisted peers and sets max connections and max peers to total number of whitelisted peers)")
	Flags.Int64(CfgP2PSendRate, 5120000, "Rate at which packets can be sent (bytes/sec)")
	Flags.Int64(CfgP2PRecvRate, 5120000, "Rate at which packets can be received (bytes/sec)")

	Flags.Uint64(CfgSubmissionGasPrice, 0, "gas price used when submitting consensus transactions")
	Flags.Uint64(CfgSubmissionMaxFee, 0, "maximum transaction fee when submitting consensus transactions")

	Flags.Bool(CfgLogDebug, false, "enable tendermint debug logs (very verbose)")

	_ = Flags.MarkHidden(CfgDebugP2PAllowDuplicateIP)
	_ = Flags.MarkHidden(CfgDebugP2PAddrBookLenient)
	_ = Flags.MarkHidden(CfgLogDebug)

	_ = viper.BindPFlags(Flags)
}
