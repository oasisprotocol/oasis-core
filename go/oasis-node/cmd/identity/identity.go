// Package identity implements the identity sub-commands.
package identity

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/identity/cometbft"
)

const CfgDataDir = "datadir"

var (
	datadirFlags = flag.NewFlagSet("", flag.ContinueOnError)

	identityCmd = &cobra.Command{
		Use:   "identity",
		Short: "identity interface utilities",
	}

	identityInitCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize node identity",
		Run:   doNodeInit,
	}

	identityShowSentryPubkeyCmd = &cobra.Command{
		Use:   "show-sentry-client-pubkey",
		Short: "outputs node's sentry control client tls public key",
		Run:   doShowSentryTLSPubkey,
	}

	identityShowTLSPubkeyCmd = &cobra.Command{
		Use:   "show-tls-pubkey",
		Short: "outputs node's endpoint tls public key",
		Run:   doShowTLSPubkey,
	}

	logger = logging.GetLogger("cmd/identity")
)

func doNodeInit(*cobra.Command, []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	// Workaround for viper bug: https://github.com/spf13/viper/issues/233
	_ = viper.BindPFlag(CfgDataDir, identityCmd.PersistentFlags().Lookup(CfgDataDir))

	dataDir := viper.GetString(CfgDataDir)
	if dataDir == "" {
		logger.Error("data directory must be set")
		os.Exit(1)
	}

	// Provision the node identity.
	nodeSignerFactory, err := fileSigner.NewFactory(dataDir, identity.RequiredSignerRoles...)
	if err != nil {
		logger.Error("failed to create identity signer factory",
			"err", err,
		)
		os.Exit(1)
	}
	if _, err = identity.LoadOrGenerate(dataDir, nodeSignerFactory); err != nil {
		logger.Error("failed to load or generate node identity",
			"err", err,
		)
		os.Exit(1)
	}

	fmt.Printf("Generated identity files in: %s\n", dataDir)
}

func doShowPubkey(_ *cobra.Command, _ []string, sentry bool) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	// Workaround for viper bug: https://github.com/spf13/viper/issues/233
	_ = viper.BindPFlag(CfgDataDir, identityCmd.PersistentFlags().Lookup(CfgDataDir))

	dataDir := viper.GetString(CfgDataDir)
	if dataDir == "" {
		logger.Error("data directory must be set")
		os.Exit(1)
	}

	nodeSignerFactory, err := fileSigner.NewFactory(dataDir, identity.RequiredSignerRoles...)
	if err != nil {
		logger.Error("failed to create node identity signer factory",
			"err", err,
		)
		os.Exit(1)
	}
	identity, err := identity.Load(dataDir, nodeSignerFactory)
	if err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	var rawCertificate []byte
	switch sentry {
	case true:
		rawCertificate = identity.TLSSentryClientCertificate.Certificate[0]
	case false:
		rawCertificate = identity.TLSCertificate.Certificate[0]
	}
	cert, err := x509.ParseCertificate(rawCertificate)
	if err != nil {
		cmdCommon.EarlyLogAndExit(fmt.Errorf("oasis: failed to parse sentry client certificate: %w", err))
	}
	pk, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		cmdCommon.EarlyLogAndExit(fmt.Errorf("oasis: bad sentry client public key type (expected: Ed25519 got: %T)", cert.PublicKey))
	}
	var pubKey signature.PublicKey
	if err := pubKey.UnmarshalBinary(pk[:]); err != nil {
		cmdCommon.EarlyLogAndExit(fmt.Errorf("oasis: sentry client public key unmarshal failure: %w", err))
	}
	key, _ := pubKey.MarshalText()

	fmt.Println(string(key))
}

func doShowTLSPubkey(cmd *cobra.Command, args []string) {
	doShowPubkey(cmd, args, false)
}

func doShowSentryTLSPubkey(cmd *cobra.Command, args []string) {
	doShowPubkey(cmd, args, true)
}

// Register registers the client sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	cometbft.Register(identityCmd)

	identityCmd.PersistentFlags().AddFlagSet(datadirFlags)

	identityInitCmd.Flags().AddFlagSet(cmdFlags.VerboseFlags)

	identityCmd.AddCommand(identityInitCmd)
	identityCmd.AddCommand(identityShowSentryPubkeyCmd)
	identityCmd.AddCommand(identityShowTLSPubkeyCmd)

	parentCmd.AddCommand(identityCmd)
}

func init() {
	datadirFlags.String(CfgDataDir, "", "data directory")
	_ = viper.BindPFlags(datadirFlags)
}
