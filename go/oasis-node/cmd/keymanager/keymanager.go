// Package keymanager implements the keymanager sub-commands.
package keymanager

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	kmApi "github.com/oasislabs/oasis-core/go/keymanager/api"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
)

const (
	cfgPolicySerial       = "keymanager.policy.serial"
	cfgPolicyID           = "keymanager.policy.id"
	cfgPolicyFile         = "keymanager.policy.file"
	cfgPolicyEnclaveID    = "keymanager.policy.enclave.id"
	cfgPolicyMayQuery     = "keymanager.policy.may.query"
	cfgPolicyMayReplicate = "keymanager.policy.may.replicate"
	cfgPolicyKeyFile      = "keymanager.policy.key.file"
	cfgPolicyTestKey      = "keymanager.policy.testkey"
	cfgPolicySigFile      = "keymanager.policy.signature.file"
	cfgPolicyIgnoreSig    = "keymanager.policy.ignore.signature"

	cfgStatusFile        = "keymanager.status.file"
	cfgStatusID          = "keymanager.status.id"
	cfgStatusInitialized = "keymanager.status.initialized"
	cfgStatusSecure      = "keymanager.status.secure"
	cfgStatusChecksum    = "keymanager.status.checksum"

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
	if err = ioutil.WriteFile(viper.GetString(cfgPolicyFile), c, 0666); err != nil {
		logger.Error("failed to write key manager policy cbor file",
			"err", err,
			"cfgPolicyFile", viper.GetString(cfgPolicyFile),
		)
		os.Exit(1)
	}

	logger.Info("generated key manager policy file",
		"PolicySGX.ID", p.ID,
	)
}

func policyFromFlags() (*kmApi.PolicySGX, error) {
	var id signature.PublicKey
	if err := id.UnmarshalHex(viper.GetString(cfgPolicyID)); err != nil {
		logger.Error("failed to parse key manager runtime ID",
			"err", err,
			"cfgPolicyID", viper.GetString(cfgPolicyID),
		)
		return nil, err
	}

	serial := viper.GetUint32(cfgPolicySerial)

	enclaves := make(map[sgx.EnclaveIdentity]*kmApi.EnclavePolicySGX)

	// Replicate and query permissions are set per-key manager enclave ID.
	// Since viper doesn't store order of arguments, go through os.Args by hand,
	// find --keymanager.policy.enclave.id and construct its permissions.
	for curArgIdx, curArg := range os.Args {
		if curArg == "--"+cfgPolicyEnclaveID {
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
				MayQuery:     make(map[signature.PublicKey][]sgx.EnclaveIdentity),
			}

			for curArgIdx = curArgIdx + 2; curArgIdx < len(os.Args); curArgIdx++ {
				// Break, if the next enclave-id is caught.
				if os.Args[curArgIdx] == "--"+cfgPolicyEnclaveID {
					break
				}

				// Catch --keymanager.policy.may.replicate option
				if os.Args[curArgIdx] == "--"+cfgPolicyMayReplicate {
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
				if os.Args[curArgIdx] == "--"+cfgPolicyMayQuery {
					queryStr := os.Args[curArgIdx+1]

					qRuntimeIDStr := strings.Split(queryStr, "=")[0]
					var qRuntimeID signature.PublicKey
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

	if err = ioutil.WriteFile(viper.GetStringSlice(cfgPolicySigFile)[0], sigBytes, 0600); err != nil {
		logger.Error("failed to write policy file signature",
			"err", err,
			"cfgPolicySigFile", viper.GetStringSlice(cfgPolicySigFile),
		)
		os.Exit(1)
	}
}

func signPolicyFromFlags() (*signature.Signature, error) {
	var signer signature.Signer
	var err error
	if viper.GetString(cfgPolicyKeyFile) != "" {
		signer, err = fileSigner.NewFactory("", signature.SignerUnknown).(*fileSigner.Factory).ForceLoad(viper.GetString(cfgPolicyKeyFile))
		if err != nil {
			return nil, err
		}
	} else if viper.GetUint(cfgPolicyTestKey) != 0 {
		if viper.GetUint(cfgPolicyTestKey) > uint(len(kmApi.TestSigners)) {
			return nil, errors.New("test key index invalid")
		}
		signer = kmApi.TestSigners[viper.GetUint(cfgPolicyTestKey)-1]
	} else {
		return nil, errors.New("no private key file or test key provided")
	}

	policyBytes, err := ioutil.ReadFile(viper.GetString(cfgPolicyFile))
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
	policyBytes, err := ioutil.ReadFile(viper.GetString(cfgPolicyFile))
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
		c, _ := json.Marshal(policy)
		fmt.Printf("%s\n", string(c))
	}

	// Check the signatures of the policy. Public key is taken from the PEM
	// signature file.
	if !viper.GetBool(cfgPolicyIgnoreSig) {
		for _, sigFile := range viper.GetStringSlice(cfgPolicySigFile) {
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

	s, err := statusFromFlags()
	if err != nil {
		logger.Error("failed to generate status",
			"err", err,
		)
		os.Exit(1)
	}

	c, _ := json.Marshal(s)
	if err = ioutil.WriteFile(viper.GetString(cfgStatusFile), c, 0666); err != nil {
		logger.Error("failed to write key manager status json file",
			"err", err,
			"cfgStatusFile", viper.GetString(cfgStatusFile),
		)
		os.Exit(1)
	}

	logger.Info("generated key manager status file",
		"Status.ID", s.ID,
	)
}

func statusFromFlags() (*kmApi.Status, error) {
	var id signature.PublicKey
	if err := id.UnmarshalHex(viper.GetString(cfgStatusID)); err != nil {
		logger.Error("failed to parse key manager status ID",
			"err", err,
			"cfgStatusID", viper.GetString(cfgStatusID),
		)
		return nil, err
	}

	// Unmarshal KM policy and its signatures.
	var signedPolicy *kmApi.SignedPolicySGX
	if viper.GetString(cfgPolicyFile) != "" {
		pb, err := ioutil.ReadFile(viper.GetString(cfgPolicyFile))
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

		for _, sigFile := range viper.GetStringSlice(cfgPolicySigFile) {
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
	if viper.GetString(cfgStatusChecksum) != "" {
		var err error
		checksum, err = hex.DecodeString(viper.GetString(cfgStatusChecksum))
		if err != nil {
			return nil, err
		}
		if len(checksum) != kmApi.ChecksumSize {
			return nil, fmt.Errorf("checksum %x is not %d bytes long", checksum, kmApi.ChecksumSize)
		}
	}

	if viper.GetString(cfgStatusChecksum) != "" && !viper.GetBool(cfgStatusInitialized) {
		return nil, fmt.Errorf("%s provided, but %s is false", cfgStatusChecksum, cfgStatusInitialized)
	}

	if viper.GetString(cfgStatusChecksum) == "" && viper.GetBool(cfgStatusInitialized) {
		return nil, fmt.Errorf("%s is true, but %s is not provided", cfgStatusInitialized, cfgStatusChecksum)
	}

	return &kmApi.Status{
		ID:            id,
		IsInitialized: viper.GetBool(cfgStatusInitialized),
		IsSecure:      viper.GetBool(cfgStatusSecure),
		Checksum:      checksum,
		Policy:        signedPolicy,
	}, nil
}

func registerKMInitPolicyFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Uint32(cfgPolicySerial, 0, "monotonically increasing number of the policy")
		cmd.Flags().String(cfgPolicyID, "", "256-bit Runtime ID this policy is valid for in hex")
		cmd.Flags().String(cfgPolicyEnclaveID, "", "512-bit Key Manager Enclave ID in hex (concatenated MRENCLAVE and MRSIGNER). Multiple Enclave IDs with corresponding permissions can be provided respectively.")
		cmd.Flags().StringSlice(cfgPolicyMayReplicate, []string{}, "enclave_id1,enclave_id2... list of new enclaves which are allowed to access the master secret. Requires "+cfgPolicyEnclaveID)
		cmd.Flags().StringToString(cfgPolicyMayQuery, map[string]string{}, "runtime_id=enclave_id1,enclave_id2... sets enclave query permission for runtime_id. Requires "+cfgPolicyEnclaveID)
	}

	cmd.Flags().AddFlagSet(policyFileFlag)

	for _, v := range []string{
		cfgPolicySerial,
		cfgPolicyID,
	} {
		_ = cmd.MarkFlagRequired(v)
	}

	for _, v := range []string{
		cfgPolicySerial,
		cfgPolicyID,
		cfgPolicyEnclaveID,
		cfgPolicyMayReplicate,
		cfgPolicyMayQuery,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

func registerKMSignPolicyFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgPolicyKeyFile, "", "input file name containing client key")
		cmd.Flags().Uint(cfgPolicyTestKey, 0, "index of test key to use (for debugging only) counting from 1")
	}

	cmd.Flags().AddFlagSet(policyFileFlag)
	cmd.Flags().AddFlagSet(policySigFileFlag)

	for _, v := range []string{
		cfgPolicyKeyFile,
		cfgPolicyTestKey,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

func registerKMVerifyPolicyFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgPolicyIgnoreSig, false, "just check, if policy file is well formed and ignore signature file")
	}

	cmd.Flags().AddFlagSet(cmdFlags.VerboseFlags)
	cmd.Flags().AddFlagSet(policyFileFlag)
	cmd.Flags().AddFlagSet(policySigFileFlag)

	for _, v := range []string{
		cfgPolicyIgnoreSig,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

func registerKMInitStatusFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgStatusID, "", "256-bit Runtime ID this status is valid for in hex")
		cmd.Flags().String(cfgStatusFile, statusFilename, "JSON output file name of status to be written")
		cmd.Flags().Bool(cfgStatusInitialized, false, "is key manager done initializing. Requires "+cfgStatusChecksum)
		cmd.Flags().Bool(cfgStatusSecure, false, "is key manager secure")
		cmd.Flags().String(cfgStatusChecksum, "", "key manager's master secret verification checksum in hex. Requires "+cfgStatusInitialized)
	}

	cmd.Flags().AddFlagSet(policyFileFlag)
	cmd.Flags().AddFlagSet(policySigFileFlag)

	for _, v := range []string{
		cfgStatusID,
	} {
		_ = cmd.MarkFlagRequired(v)
	}

	for _, v := range []string{
		cfgStatusID,
		cfgStatusFile,
		cfgStatusInitialized,
		cfgStatusSecure,
		cfgStatusChecksum,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

// Register registers the keymanager sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	policyFileFlag.String(cfgPolicyFile, policyFilename, "file name of policy in CBOR format")
	policySigFileFlag.StringSlice(cfgPolicySigFile, []string{policyFilename + ".sign"}, "file name(s) containing policy signature")

	_ = viper.BindPFlags(policyFileFlag)
	_ = viper.BindPFlags(policySigFileFlag)

	for _, v := range []*cobra.Command{
		initPolicyCmd,
		signPolicyCmd,
		verifyPolicyCmd,
		initStatusCmd,
	} {
		keyManagerCmd.AddCommand(v)
	}

	registerKMInitPolicyFlags(initPolicyCmd)
	registerKMSignPolicyFlags(signPolicyCmd)
	registerKMVerifyPolicyFlags(verifyPolicyCmd)
	registerKMInitStatusFlags(initStatusCmd)

	parentCmd.AddCommand(keyManagerCmd)
}
