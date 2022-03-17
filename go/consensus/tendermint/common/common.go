package common

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

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
	// CfgP2PMaxNumInboundPeers configures the max number of inbound peers.
	CfgP2PMaxNumInboundPeers = "consensus.tendermint.p2p.max_num_inbound_peers"
	// CfgP2PMaxNumOutboundPeers configures the max number of outbound peers, excluding persistent peers.
	CfgP2PMaxNumOutboundPeers = "consensus.tendermint.p2p.max_num_outbound_peers"
	// CfgP2PSendRate is the rate at which packets can be sent, in bytes/second.
	CfgP2PSendRate = "consensus.tendermint.p2p.send_rate"
	// CfgP2PRecvRate is the rate at which packets can be received, in bytes/second.
	CfgP2PRecvRate = "consensus.tendermint.p2p.recv_rate"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

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
	Flags.Int(CfgP2PMaxNumInboundPeers, 100, "Max number of inbound peers")
	Flags.Int(CfgP2PMaxNumOutboundPeers, 20, "Max number of outbound peers (excluding persistent peers)")
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
