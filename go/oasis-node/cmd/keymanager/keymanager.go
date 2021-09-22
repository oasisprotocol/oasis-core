// Package keymanager implements the keymanager sub-commands.
package keymanager

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	kmApi "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	cmdContext "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/context"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
)

const (
	CfgPolicySerial       = "keymanager.policy.serial"
	CfgPolicyID           = "keymanager.policy.id"
	CfgPolicyFile         = "keymanager.policy.file"
	CfgPolicyEnclaveID    = "keymanager.policy.enclave.id"
	CfgPolicyMayQuery     = "keymanager.policy.may.query"
	CfgPolicyMayReplicate = "keymanager.policy.may.replicate"
	CfgPolicyKeyFile      = "keymanager.policy.key.file"
	CfgPolicyTestKey      = "keymanager.policy.testkey"
	CfgPolicySigFile      = "keymanager.policy.signature.file"
	CfgPolicyIgnoreSig    = "keymanager.policy.ignore.signature"

	CfgStatusFile        = "keymanager.status.file"
	CfgStatusID          = "keymanager.status.id"
	CfgStatusInitialized = "keymanager.status.initialized"
	CfgStatusSecure      = "keymanager.status.secure"
	CfgStatusChecksum    = "keymanager.status.checksum"

	policyFilename = "km_policy.cbor"
	statusFilename = "km_status.json"
)

var (
	policyFileFlag    = flag.NewFlagSet("", flag.ContinueOnError)
	policySigFileFlag = flag.NewFlagSet("", flag.ContinueOnError)

	keyManagerCmd = &cobra.Command{
		Use:   "keymanager",
		Short: "keymanager utilities",
	}

	initPolicyCmd = &cobra.Command{
		Use:   "init_policy",
		Short: "generate keymanager policy file",
		Run:   doInitPolicy,
	}

	signPolicyCmd = &cobra.Command{
		Use:   "sign_policy",
		Short: "sign keymanager policy file",
		Run:   doSignPolicy,
	}

	verifyPolicyCmd = &cobra.Command{
		Use:   "verify_policy",
		Short: "verify keymanager policy file and (optionally) its signature",
		Run:   doVerifyPolicy,
	}

	initStatusCmd = &cobra.Command{
		Use:   "init_status",
		Short: "generate keymanager status file",
		Run:   doInitStatus,
	}

	genUpdateCmd = &cobra.Command{
		Use:   "gen_update",
		Short: "generate a update transaction",
		Run:   doGenUpdate,
	}

	logger = logging.GetLogger("cmd/keymanager")
)

func doInitPolicy(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	p, err := policyFromFlags()
	if err != nil {
		os.Exit(1)
	}

	c := cbor.Marshal(p)
	if err = ioutil.WriteFile(viper.GetString(CfgPolicyFile), c, 0o644); err != nil { // nolint: gosec
		logger.Error("failed to write key manager policy cbor file",
			"err", err,
			"CfgPolicyFile", viper.GetString(CfgPolicyFile),
		)
		os.Exit(1)
	}

	logger.Info("generated key manager policy file",
		"PolicySGX.ID", p.ID,
	)
}

func policyFromFlags() (*kmApi.PolicySGX, error) {
	var id common.Namespace
	if err := id.UnmarshalHex(viper.GetString(CfgPolicyID)); err != nil {
		logger.Error("failed to parse key manager runtime ID",
			"err", err,
			"CfgPolicyID", viper.GetString(CfgPolicyID),
		)
		return nil, err
	}

	serial := viper.GetUint32(CfgPolicySerial)

	enclaves := make(map[sgx.EnclaveIdentity]*kmApi.EnclavePolicySGX)

	// Replicate and query permissions are set per-key manager enclave ID.
	// Since viper doesn't store order of arguments, go through os.Args by hand,
	// find --keymanager.policy.enclave.id and construct its permissions.
	for curArgIdx, curArg := range os.Args {
		if curArg == "--"+CfgPolicyEnclaveID {
			kmEnclaveIDStr := os.Args[curArgIdx+1]
			kmEnclaveID := sgx.EnclaveIdentity{}
			if err := kmEnclaveID.UnmarshalHex(kmEnclaveIDStr); err != nil {
				logger.Error("failed to parse key manager enclave ID",
					"err", err,
				)
				return nil, err
			}

			enclaves[kmEnclaveID] = &kmApi.EnclavePolicySGX{
				MayReplicate: []sgx.EnclaveIdentity{},
				MayQuery:     make(map[common.Namespace][]sgx.EnclaveIdentity),
			}

			for curArgIdx = curArgIdx + 2; curArgIdx < len(os.Args); curArgIdx++ {
				// Break, if the next enclave-id is caught.
				if os.Args[curArgIdx] == "--"+CfgPolicyEnclaveID {
					break
				}

				// Catch --keymanager.policy.may.replicate option
				if os.Args[curArgIdx] == "--"+CfgPolicyMayReplicate {
					replicateStr := os.Args[curArgIdx+1]
					for _, r := range strings.Split(replicateStr, ",") {
						replEnclaveID := sgx.EnclaveIdentity{}
						if err := replEnclaveID.UnmarshalHex(r); err != nil {
							logger.Error("failed to parse may-replicate enclave ID",
								"err", err,
								"given_replicate_enclave_id", r,
							)
							return nil, err
						}
						enclaves[kmEnclaveID].MayReplicate = append(enclaves[kmEnclaveID].MayReplicate, replEnclaveID)
					}
				}

				// Catch --keymanager.policy.may.query option
				if os.Args[curArgIdx] == "--"+CfgPolicyMayQuery {
					queryStr := os.Args[curArgIdx+1]

					qRuntimeIDStr := strings.Split(queryStr, "=")[0]
					var qRuntimeID common.Namespace
					if err := qRuntimeID.UnmarshalHex(qRuntimeIDStr); err != nil {
						logger.Error("failed to parse may-query runtime ID",
							"err", err,
							"given_query_runtime_id", qRuntimeIDStr,
						)
						return nil, err
					}

					queryEnclaveIDs := []sgx.EnclaveIdentity{}
					for _, queryEnclaveIDStr := range strings.Split(strings.Split(queryStr, "=")[1], ",") {
						queryEnclaveID := sgx.EnclaveIdentity{}
						if err := queryEnclaveID.UnmarshalHex(queryEnclaveIDStr); err != nil {
							logger.Error("failed to parse may-query enclave ID",
								"err", err,
								"given_query_enclave_id", queryEnclaveIDStr,
							)
							return nil, err
						}
						queryEnclaveIDs = append(queryEnclaveIDs, queryEnclaveID)
					}
					enclaves[kmEnclaveID].MayQuery[qRuntimeID] = queryEnclaveIDs
				}
			}
		}
	}

	return &kmApi.PolicySGX{
		Serial:   serial,
		ID:       id,
		Enclaves: enclaves,
	}, nil
}

func doSignPolicy(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	sig, err := signPolicyFromFlags()
	if err != nil {
		logger.Error("failed to sign policy",
			"err", err,
		)
		os.Exit(1)
	}

	sigBytes, err := sig.MarshalPEM()
	if err != nil {
		logger.Error("failed to generate pem signature",
			"err", err,
		)
		os.Exit(1)
	}

	if err = ioutil.WriteFile(viper.GetStringSlice(CfgPolicySigFile)[0], sigBytes, 0o600); err != nil {
		logger.Error("failed to write policy file signature",
			"err", err,
			"CfgPolicySigFile", viper.GetStringSlice(CfgPolicySigFile),
		)
		os.Exit(1)
	}
}

func signPolicyFromFlags() (*signature.Signature, error) {
	var signer signature.Signer
	var err error
	if viper.GetString(CfgPolicyKeyFile) != "" {
		var signerFactory signature.SignerFactory
		signerFactory, err = fileSigner.NewFactory("", signature.SignerUnknown)
		if err != nil {
			return nil, err
		}
		signer, err = signerFactory.(*fileSigner.Factory).ForceLoad(viper.GetString(CfgPolicyKeyFile))
		if err != nil {
			return nil, err
		}
	} else if viper.GetUint(CfgPolicyTestKey) != 0 {
		if !cmdFlags.DebugDontBlameOasis() {
			return nil, errors.New("refusing to use test keys for signing")
		}
		if viper.GetUint(CfgPolicyTestKey) > uint(len(kmApi.TestSigners)) {
			return nil, errors.New("test key index invalid")
		}
		signer = kmApi.TestSigners[viper.GetUint(CfgPolicyTestKey)-1]
	} else {
		return nil, errors.New("no private key file or test key provided")
	}

	policyBytes, err := ioutil.ReadFile(viper.GetString(CfgPolicyFile))
	if err != nil {
		return nil, err
	}

	// Check whether input policy file is well formed.
	if _, err = unmarshalPolicyCBOR(policyBytes); err != nil {
		return nil, err
	}

	rawSigBytes, err := signer.ContextSign(kmApi.PolicySGXSignatureContext, policyBytes)
	if err != nil {
		return nil, err
	}

	rawSig := signature.RawSignature{}
	copy(rawSig[:], rawSigBytes)

	return &signature.Signature{
		PublicKey: signer.Public(),
		Signature: rawSig,
	}, nil
}

func doVerifyPolicy(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	if err := verifyPolicyFromFlags(); err != nil {
		logger.Error("failed to verify policy",
			"err", err,
		)
		os.Exit(1)
	}
}

func verifyPolicyFromFlags() error {
	policyBytes, err := ioutil.ReadFile(viper.GetString(CfgPolicyFile))
	if err != nil {
		return err
	}

	// Check whether input policy file is well formed.
	policy, err := unmarshalPolicyCBOR(policyBytes)
	if err != nil {
		return err
	}

	// Output policy content in JSON, if verbose switch given.
	if cmdFlags.Verbose() {
		prettyPolicy, err := cmdCommon.PrettyJSONMarshal(policy)
		if err != nil {
			logger.Error("failed to get pretty JSON of policy",
				"err", err,
			)
			os.Exit(1)
		}
		fmt.Println(string(prettyPolicy))
	}

	// Check the signatures of the policy. Public key is taken from the PEM
	// signature file.
	if !viper.GetBool(CfgPolicyIgnoreSig) {
		for _, sigFile := range viper.GetStringSlice(CfgPolicySigFile) {
			policySigBytes, err := ioutil.ReadFile(sigFile)
			if err != nil {
				return err
			}

			s := signature.Signature{}
			if err := s.UnmarshalPEM(policySigBytes); err != nil {
				return err
			}

			if !s.Verify(kmApi.PolicySGXSignatureContext, policyBytes) {
				return errors.New("signature is not valid for given policy")
			}
		}
	}

	return nil
}

/// unmarshalPolicyChor checks whether given CBOR is a valid kmApi.PolicySGX struct.
func unmarshalPolicyCBOR(pb []byte) (*kmApi.PolicySGX, error) {
	var p *kmApi.PolicySGX = &kmApi.PolicySGX{}
	if err := cbor.Unmarshal(pb, p); err != nil {
		return nil, err
	}

	// Re-marshal to check the canonicity.
	pb2 := cbor.Marshal(p)
	if !bytes.Equal(pb, pb2) {
		return nil, errors.New("policy file not in canonical form")
	}

	return p, nil
}

func doInitStatus(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	status, err := statusFromFlags()
	if err != nil {
		logger.Error("failed to generate status",
			"err", err,
		)
		os.Exit(1)
	}

	prettyStatus, err := cmdCommon.PrettyJSONMarshal(status)
	if err != nil {
		logger.Error("failed to get pretty JSON of key manager status",
			"err", err,
		)
		os.Exit(1)
	}
	if err = ioutil.WriteFile(viper.GetString(CfgStatusFile), prettyStatus, 0o644); err != nil { // nolint: gosec
		logger.Error("failed to write key manager status json file",
			"err", err,
			"CfgStatusFile", viper.GetString(CfgStatusFile),
		)
		os.Exit(1)
	}

	logger.Info("generated key manager status file",
		"Status.ID", status.ID,
	)
}

func doGenUpdate(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	genesis := cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	// Assemble the SignedPolicySGX from the policy document and detached
	// signatures.
	var signedPolicy kmApi.SignedPolicySGX

	policyBytes, err := ioutil.ReadFile(viper.GetString(CfgPolicyFile))
	if err != nil {
		logger.Error("failed to read policy file",
			"err", err,
		)
		os.Exit(1)
	}
	if err = cbor.Unmarshal(policyBytes, &signedPolicy.Policy); err != nil {
		logger.Error("failed to unmarshal policy file",
			"err", err,
		)
		os.Exit(1)
	}

	for _, sigFile := range viper.GetStringSlice(CfgPolicySigFile) {
		var policySigBytes []byte
		if policySigBytes, err = ioutil.ReadFile(sigFile); err != nil {
			logger.Error("failed to read signature file",
				"err", err,
				"sig_file", sigFile,
			)
			os.Exit(1)
		}

		var s signature.Signature
		if err = s.UnmarshalPEM(policySigBytes); err != nil {
			logger.Error("failed to unmarshal signature",
				"err", err,
				"sig_file", sigFile,
			)
			os.Exit(1)
		}
		signedPolicy.Signatures = append(signedPolicy.Signatures, s)
	}

	// Validate the SignedPolicySGX.
	if err = kmApi.SanityCheckSignedPolicySGX(nil, &signedPolicy); err != nil {
		logger.Error("failed to validate SignedPolicySGX",
			"err", err,
		)
		os.Exit(1)
	}

	// Build, sign, and write the UpdatePolicy transaction.
	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := kmApi.NewUpdatePolicyTx(nonce, fee, &signedPolicy)
	cmdConsensus.SignAndSaveTx(cmdContext.GetCtxWithGenesisInfo(genesis), tx, nil)
}

func statusFromFlags() (*kmApi.Status, error) {
	var id common.Namespace
	if err := id.UnmarshalHex(viper.GetString(CfgStatusID)); err != nil {
		logger.Error("failed to parse key manager status ID",
			"err", err,
			"CfgStatusID", viper.GetString(CfgStatusID),
		)
		return nil, err
	}

	// Unmarshal KM policy and its signatures.
	var signedPolicy *kmApi.SignedPolicySGX
	if viper.GetString(CfgPolicyFile) != "" {
		pb, err := ioutil.ReadFile(viper.GetString(CfgPolicyFile))
		if err != nil {
			return nil, err
		}

		p, err := unmarshalPolicyCBOR(pb)
		if err != nil {
			return nil, err
		}
		signedPolicy = &kmApi.SignedPolicySGX{
			Policy: *p,
		}

		for _, sigFile := range viper.GetStringSlice(CfgPolicySigFile) {
			sigBytes, err := ioutil.ReadFile(sigFile)
			if err != nil {
				return nil, err
			}

			s := signature.Signature{}
			if err := s.UnmarshalPEM(sigBytes); err != nil {
				return nil, err
			}

			signedPolicy.Signatures = append(signedPolicy.Signatures, s)
		}
	}

	checksum := []byte{}
	if viper.GetString(CfgStatusChecksum) != "" {
		var err error
		checksum, err = hex.DecodeString(viper.GetString(CfgStatusChecksum))
		if err != nil {
			return nil, err
		}
		if len(checksum) != kmApi.ChecksumSize {
			return nil, fmt.Errorf("checksum %x is not %d bytes long", checksum, kmApi.ChecksumSize)
		}
	}

	if viper.GetString(CfgStatusChecksum) != "" && !viper.GetBool(CfgStatusInitialized) {
		return nil, fmt.Errorf("%s provided, but %s is false", CfgStatusChecksum, CfgStatusInitialized)
	}

	if viper.GetString(CfgStatusChecksum) == "" && viper.GetBool(CfgStatusInitialized) {
		return nil, fmt.Errorf("%s is true, but %s is not provided", CfgStatusInitialized, CfgStatusChecksum)
	}

	return &kmApi.Status{
		ID:            id,
		IsInitialized: viper.GetBool(CfgStatusInitialized),
		IsSecure:      viper.GetBool(CfgStatusSecure),
		Checksum:      checksum,
		Policy:        signedPolicy,
	}, nil
}

func registerKMInitPolicyFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Uint32(CfgPolicySerial, 0, "monotonically increasing number of the policy")
		cmd.Flags().String(CfgPolicyID, "", "256-bit Runtime ID this policy is valid for in hex")
		cmd.Flags().String(CfgPolicyEnclaveID, "", "512-bit Key Manager Enclave ID in hex (concatenated MRENCLAVE and MRSIGNER). Multiple Enclave IDs with corresponding permissions can be provided respectively.")
		cmd.Flags().StringSlice(CfgPolicyMayReplicate, []string{}, "enclave_id1,enclave_id2... list of new enclaves which are allowed to access the master secret. Requires "+CfgPolicyEnclaveID)
		cmd.Flags().StringToString(CfgPolicyMayQuery, map[string]string{}, "runtime_id=enclave_id1,enclave_id2... sets enclave query permission for runtime_id. Requires "+CfgPolicyEnclaveID)
	}

	cmd.Flags().AddFlagSet(policyFileFlag)

	for _, v := range []string{
		CfgPolicySerial,
		CfgPolicyID,
	} {
		_ = cmd.MarkFlagRequired(v)
	}

	for _, v := range []string{
		CfgPolicySerial,
		CfgPolicyID,
		CfgPolicyEnclaveID,
		CfgPolicyMayReplicate,
		CfgPolicyMayQuery,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

func registerKMSignPolicyFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(CfgPolicyKeyFile, "", "input file name containing client key")
		cmd.Flags().Uint(CfgPolicyTestKey, 0, "index of test key to use (for debugging only) counting from 1")
		_ = cmd.Flags().MarkHidden(CfgPolicyTestKey)
	}

	cmd.Flags().AddFlagSet(policyFileFlag)
	cmd.Flags().AddFlagSet(policySigFileFlag)
	cmd.Flags().AddFlagSet(cmdFlags.DebugDontBlameOasisFlag)

	for _, v := range []string{
		CfgPolicyKeyFile,
		CfgPolicyTestKey,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

func registerKMVerifyPolicyFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(CfgPolicyIgnoreSig, false, "just check, if policy file is well formed and ignore signature file")
	}

	cmd.Flags().AddFlagSet(cmdFlags.VerboseFlags)
	cmd.Flags().AddFlagSet(policyFileFlag)
	cmd.Flags().AddFlagSet(policySigFileFlag)

	for _, v := range []string{
		CfgPolicyIgnoreSig,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

func registerKMInitStatusFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(CfgStatusID, "", "256-bit Runtime ID this status is valid for in hex")
		cmd.Flags().String(CfgStatusFile, statusFilename, "JSON output file name of status to be written")
		cmd.Flags().Bool(CfgStatusInitialized, false, "is key manager done initializing. Requires "+CfgStatusChecksum)
		cmd.Flags().Bool(CfgStatusSecure, false, "is key manager secure")
		cmd.Flags().String(CfgStatusChecksum, "", "key manager's master secret verification checksum in hex. Requires "+CfgStatusInitialized)
	}

	cmd.Flags().AddFlagSet(policyFileFlag)
	cmd.Flags().AddFlagSet(policySigFileFlag)

	for _, v := range []string{
		CfgStatusID,
	} {
		_ = cmd.MarkFlagRequired(v)
	}

	for _, v := range []string{
		CfgStatusID,
		CfgStatusFile,
		CfgStatusInitialized,
		CfgStatusSecure,
		CfgStatusChecksum,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

// Register registers the keymanager sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	policyFileFlag.String(CfgPolicyFile, policyFilename, "file name of policy in CBOR format")
	policySigFileFlag.StringSlice(CfgPolicySigFile, []string{policyFilename + ".sign"}, "file name(s) containing policy signature")

	_ = viper.BindPFlags(policyFileFlag)
	_ = viper.BindPFlags(policySigFileFlag)

	for _, v := range []*cobra.Command{
		initPolicyCmd,
		signPolicyCmd,
		verifyPolicyCmd,
		initStatusCmd,
		genUpdateCmd,
	} {
		keyManagerCmd.AddCommand(v)
	}

	registerKMInitPolicyFlags(initPolicyCmd)
	registerKMSignPolicyFlags(signPolicyCmd)
	registerKMVerifyPolicyFlags(verifyPolicyCmd)
	registerKMInitStatusFlags(initStatusCmd)

	genUpdateCmd.Flags().AddFlagSet(policyFileFlag)
	genUpdateCmd.Flags().AddFlagSet(policySigFileFlag)
	genUpdateCmd.Flags().AddFlagSet(cmdConsensus.TxFlags)
	genUpdateCmd.Flags().AddFlagSet(cmdFlags.AssumeYesFlag)

	parentCmd.AddCommand(keyManagerCmd)
}
