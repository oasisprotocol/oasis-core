package pcs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

const (
	// requiredTCBInfoVersion is the required TCB info version.
	requiredTCBInfoVersion = 3

	// requiredQEIdentityVersion is the required QE identity version.
	requiredQEIdentityVersion = 2
)

// If set, the TCB verification will be done in a more lax manner.
var unsafeLaxVerify bool

// TimestampFormat is the format of the TCB timestamp, suitable for use with time.Parse.
//
// Workaround for https://github.com/golang/go/issues/21990
const TimestampFormat = "2006-01-02T15:04:05.999999999Z"

// SetUnsafeLaxVerify enables the unsafe, more lax TCB status verification.
//
// OutOfDate and OutOfDateConfigurationNeeded TCB statuses will be treated as valid.
func SetUnsafeLaxVerify() {
	unsafeLaxVerify = true
}

// TCBBundle contains all the required components to verify a quote's TCB.
type TCBBundle struct {
	TCBInfo      SignedTCBInfo    `json:"tcb_info"`
	QEIdentity   SignedQEIdentity `json:"qe_id"`
	Certificates []byte           `json:"certs"`
}

// Verify verifies the TCB info and the QE identity corresponding to the passed SVN information.
func (bnd *TCBBundle) Verify(
	teeType TeeType,
	ts time.Time,
	policy *QuotePolicy,
	fmspc []byte,
	sgxCompSvn [16]int32,
	tdxCompSvn *[16]byte,
	pcesvn uint16,
	qe *SgxReport,
) error {
	pk, err := bnd.getPublicKey(ts)
	if err != nil {
		return err
	}
	err = bnd.verifyQEIdentity(teeType, ts, pk, policy, qe)
	if err != nil {
		return fmt.Errorf("pcs/tcb: failed to verify QE identity: %w", err)
	}
	err = bnd.verifyTCBInfo(teeType, ts, pk, policy, fmspc, sgxCompSvn, tdxCompSvn, pcesvn)
	if err != nil {
		return fmt.Errorf("pcs/tcb: failed to verify TCB info: %w", err)
	}
	return nil
}

// verifyQEIdentity verifies the QE identity.
func (bnd *TCBBundle) verifyQEIdentity(
	teeType TeeType,
	ts time.Time,
	pk *ecdsa.PublicKey,
	policy *QuotePolicy,
	qe *SgxReport,
) error {
	qeInfo, err := bnd.QEIdentity.open(teeType, ts, policy, pk)
	if err != nil {
		return fmt.Errorf("pcs/tcb: invalid QE identity: %w", err)
	}
	return qeInfo.verify(qe)
}

// verifyTCBInfo verifies the TCB level and the FMSPC.
func (bnd *TCBBundle) verifyTCBInfo(
	teeType TeeType,
	ts time.Time,
	pk *ecdsa.PublicKey,
	policy *QuotePolicy,
	fmspc []byte,
	sgxCompSvn [16]int32,
	tdxCompSvn *[16]byte,
	pcesvn uint16,
) error {
	tcbInfo, err := bnd.TCBInfo.open(teeType, ts, policy, pk)
	if err != nil {
		return fmt.Errorf("pcs/tcb: invalid TCB info: %w", err)
	}
	err = tcbInfo.validateFMSPC(fmspc)
	if err != nil {
		return fmt.Errorf("pcs/tcb: failed to validate FMSPC: %w", err)
	}
	err = tcbInfo.validateTCBLevel(sgxCompSvn, tdxCompSvn, pcesvn)
	if err != nil {
		return fmt.Errorf("pcs/tcb: failed to validate TCB level: %w", err)
	}

	return nil
}

func (bnd *TCBBundle) getPublicKey(ts time.Time) (*ecdsa.PublicKey, error) {
	var certs []*x509.Certificate
	data := bnd.Certificates
	for len(data) > 0 {
		var (
			cert *x509.Certificate
			err  error
		)
		if cert, data, err = CertFromPEM(data); err != nil {
			return nil, fmt.Errorf("pcs/tcb: bad X509 certificate in TCB bundle: %w", err)
		}
		if cert == nil {
			break
		}
		certs = append(certs, cert)
	}
	if len(certs) != 2 {
		return nil, fmt.Errorf("pcs/tcb: unexpected certificate chain length: %d", len(certs))
	}
	tcbCert, rootCert := certs[0], certs[1]

	// Verify certificate chain.
	certChains, err := tcbCert.Verify(x509.VerifyOptions{
		Roots:       IntelTrustRoots,
		CurrentTime: ts,
	})
	if err != nil {
		return nil, fmt.Errorf("pcs/tcb: failed to verify TCB info certificate chain: %w", err)
	}
	if len(certChains) != 1 {
		return nil, fmt.Errorf("pcs/tcb: unexpected number of chains: %d", len(certChains))
	}
	chain := certChains[0]

	if !chain[len(chain)-1].Equal(rootCert) {
		return nil, fmt.Errorf("pcs/tcb: unexpected root in certificate chain")
	}

	// Extract TCB signing key.
	pk, ok := tcbCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pcs/tcb: TCB certificate with non-ECDSA signature scheme")
	}

	return pk, nil
}

func verifyTCBSignature(data json.RawMessage, signature string, pk *ecdsa.PublicKey) error {
	var sig SignatureECDSA_P256
	if err := sig.UnmarshalHex(signature); err != nil {
		return err
	}

	if h := sha256.Sum256(data); !sig.Verify(pk, h[:]) {
		return fmt.Errorf("pcs/tcb: TCB signature verification failed")
	}
	return nil
}

// SignedTCBInfo is the signed TCB info structure.
type SignedTCBInfo struct {
	TCBInfo   json.RawMessage `cbor:"tcb_info" json:"tcbInfo"`
	Signature string          `cbor:"signature" json:"signature"`
}

// Open verifies the signature and unmarshals the inner TCB info.
func (st *SignedTCBInfo) open(teeType TeeType, ts time.Time, policy *QuotePolicy, pk *ecdsa.PublicKey) (*TCBInfo, error) {
	if err := verifyTCBSignature(st.TCBInfo, st.Signature, pk); err != nil {
		return nil, err
	}

	var tcbInfo TCBInfo
	if err := json.Unmarshal(st.TCBInfo, &tcbInfo); err != nil {
		return nil, fmt.Errorf("pcs/tcb: malformed TCB info body: %w", err)
	}
	if err := tcbInfo.validate(teeType, ts, policy); err != nil {
		return nil, err
	}
	return &tcbInfo, nil
}

// TDXModule is a representation of the properties of Intel's TDX SEAM module.
type TDXModule struct {
	MRSIGNER       string `json:"mrsigner"`
	Attributes     string `json:"attributes"`
	AttributesMask string `json:"attributesMask"`
}

// TDXModuleIdentity is a representation of the identity of the Intel's TDX SEAM module in case the
// platform supports more than one TDX SEAM module.
type TDXModuleIdentity struct {
	ID        string            `json:"id"`
	TCBLevels []EnclaveTCBLevel `json:"tcbLevels"`
	TDXModule
}

const (
	tcbInfoSGX = "SGX"
	tcbInfoTDX = "TDX"
)

// TCBInfo is the TCB info body.
type TCBInfo struct {
	ID                      string              `json:"id"`
	Version                 int                 `json:"version"`
	IssueDate               string              `json:"issueDate"`
	NextUpdate              string              `json:"nextUpdate"`
	FMSPC                   string              `json:"fmspc"`
	PCEID                   string              `json:"pceId"`
	TCBType                 int                 `json:"tcbType"`
	TCBEvaluationDataNumber uint32              `json:"tcbEvaluationDataNumber"`
	TDXModule               TDXModule           `json:"tdxModule,omitempty"`
	TDXModuleIdentities     []TDXModuleIdentity `json:"tdxModuleIdentities,omitempty"`
	TCBLevels               []TCBLevel          `json:"tcbLevels"`
}

func (ti *TCBInfo) validate(teeType TeeType, ts time.Time, policy *QuotePolicy) error {
	switch teeType {
	case TeeTypeSGX:
		if ti.ID != tcbInfoSGX {
			return fmt.Errorf("pcs/tcb: unexpected TCB info identifier: %s", ti.ID)
		}
	case TeeTypeTDX:
		if ti.ID != tcbInfoTDX {
			return fmt.Errorf("pcs/tcb: unexpected TCB info identifier: %s", ti.ID)
		}
	default:
		return fmt.Errorf("pcs/tcb: unsupported TEE type")
	}

	if ti.Version != requiredTCBInfoVersion {
		return fmt.Errorf("pcs/tcb: unexpected TCB info version: %d", ti.Version)
	}

	// Validate TCB info is not expired/not yet valid based on current time.
	var (
		issueDate time.Time
		err       error
	)
	if issueDate, err = time.Parse(TimestampFormat, ti.IssueDate); err != nil {
		return fmt.Errorf("pcs/tcb: invalid issue date: %w", err)
	}
	if _, err = time.Parse(TimestampFormat, ti.NextUpdate); err != nil {
		return fmt.Errorf("pcs/tcb: invalid next update date: %w", err)
	}

	if issueDate.After(ts) {
		return fmt.Errorf("pcs/tcb: TCB info issue date in the future")
	}
	if ts.Sub(issueDate).Nanoseconds() > int64(policy.TCBValidityPeriod)*24*int64(time.Hour) {
		return fmt.Errorf("pcs/tcb: TCB info expired")
	}

	if ti.TCBEvaluationDataNumber < policy.MinTCBEvaluationDataNumber {
		return fmt.Errorf("pcs/tcb: invalid TCB evaluation data number")
	}

	// Validate FMSPC is whitelisted.
	if len(policy.FMSPCWhitelist) > 0 && !slices.Contains(policy.FMSPCWhitelist, ti.FMSPC) {
		return fmt.Errorf("pcs/tcb: FMSPC is not whitelisted")
	}

	// Validate FMSPC is not blacklisted.
	if slices.Contains(policy.FMSPCBlacklist, ti.FMSPC) {
		return fmt.Errorf("pcs/tcb: FMSPC is blacklisted")
	}

	return nil
}

func (ti *TCBInfo) validateFMSPC(fmspc []byte) error {
	// Validate FMSPC matches.
	expectedFmspc, err := hex.DecodeString(ti.FMSPC)
	if err != nil {
		return fmt.Errorf("pcs/tcb: malformed FMSPC: %w", err)
	}
	if !bytes.Equal(fmspc, expectedFmspc) {
		return fmt.Errorf("pcs/tcb: FMSPC: mismatch (expected: %X got: %X)", expectedFmspc, fmspc)
	}

	return nil
}

func (ti *TCBInfo) validateTCBLevel(
	sgxCompSvn [16]int32,
	tdxCompSvn *[16]byte,
	pcesvn uint16,
) error {
	tcbLevel, err := ti.getTCBLevel(sgxCompSvn, tdxCompSvn, pcesvn)
	if err != nil {
		return fmt.Errorf("pcs/tcb: failed to get TCB level: %w", err)
	}

	switch tcbLevel.Status {
	case StatusUpToDate, StatusSWHardeningNeeded:
		// These are ok.
		return nil
	case StatusOutOfDate, StatusConfigurationNeeded, StatusOutOfDateConfigurationNeeded:
		// Ok if lax verification.
		if unsafeLaxVerify {
			return nil
		}
	default:
		// Not ok.
	}

	return &TCBOutOfDateError{
		Kind:        TCBKindPlatform,
		Status:      tcbLevel.Status,
		AdvisoryIDs: tcbLevel.AdvisoryIDs,
	}
}

func (ti *TCBInfo) getTCBLevel(
	sgxCompSvn [16]int32,
	tdxCompSvn *[16]byte,
	pcesvn uint16,
) (*TCBLevel, error) {
	// Find first matching TCB level.
	var matchedTCBLevel *TCBLevel
	for i, tcbLevel := range ti.TCBLevels {
		if !tcbLevel.matches(sgxCompSvn, tdxCompSvn, pcesvn) {
			continue
		}
		matchedTCBLevel = &ti.TCBLevels[i]
		break
	}
	if matchedTCBLevel == nil {
		return nil, fmt.Errorf("pcs/tcb: TCB level not supported")
	}

	if matchedTCBLevel.Status == statusFieldMissing {
		return nil, fmt.Errorf("pcs/tcb: missing TCB status")
	}

	if ti.ID == tcbInfoTDX {
		// Perform additional TCB status evaluation for TDX module in case TEE TCB SVN at index 1 is
		// greater or equal to 1, otherwise finish the comparison logic.
		if tdxCompSvn == nil {
			return nil, fmt.Errorf("pcs/tcb: missing TDX SVN components")
		}
		if tdxModuleVersion := (*tdxCompSvn)[1]; tdxModuleVersion >= 1 {
			// In order to determine TCB status of TDX module, find a matching TDX Module Identity
			// (in tdxModuleIdentities array of TCB Info) with its id set to "TDX_<version>" where
			// <version> matches the value of TEE TCB SVN at index 1. If a matching TDX Module
			// Identity cannot be found, fail.
			tdxModuleID := fmt.Sprintf("TDX_%02d", tdxModuleVersion)
			idx := slices.IndexFunc(ti.TDXModuleIdentities, func(tm TDXModuleIdentity) bool {
				return tm.ID == tdxModuleID
			})
			if idx < 0 {
				return nil, fmt.Errorf("pcs/tcb: TDX module not supported")
			}
			// Otherwise, for the selected TDX Module Identity go over the sorted collection of TCB
			// Levels starting from the first item on the list and compare its isvsvn value to the
			// TEE TCB SVN at index 0. If TEE TCB SVN at index 0 is greater or equal to its value,
			// read tcbStatus assigned to this TCB level, otherwise move to the next item on TCB
			// levels list.
			tdxModule := ti.TDXModuleIdentities[idx]
			var matchedModuleTCBLevel *EnclaveTCBLevel
			for i, tcbLevel := range tdxModule.TCBLevels {
				if tcbLevel.TCB.ISVSVN > uint16((*tdxCompSvn)[0]) {
					continue
				}
				matchedModuleTCBLevel = &tdxModule.TCBLevels[i]
				break
			}
			if matchedModuleTCBLevel == nil {
				return nil, fmt.Errorf("pcs/tcb: TDX module TCB level not supported")
			}
			if matchedModuleTCBLevel.Status != StatusUpToDate {
				return nil, &TCBOutOfDateError{
					Kind:        TCBKindEnclave,
					Status:      matchedModuleTCBLevel.Status,
					AdvisoryIDs: matchedModuleTCBLevel.AdvisoryIDs,
				}
			}
		}
	}

	return matchedTCBLevel, nil
}

// TCBKind is the kind of the TCB.
type TCBKind uint8

const (
	// TCBKindPlatform is the platform TCB kind (e.g. the CPU/microcode/config).
	TCBKindPlatform = 0
	// TCBKindEnclave is the enclave TCB kind (e.g. the QE).
	TCBKindEnclave = 1
)

// String returns a string representation of the TCB kind.
func (tk TCBKind) String() string {
	switch tk {
	case TCBKindPlatform:
		return "platform"
	case TCBKindEnclave:
		return "QE"
	default:
		return "[unknown]"
	}
}

// TCBOutOfDateError is an error saying that the TCB of the platform or enclave is out of date.
type TCBOutOfDateError struct {
	Kind        TCBKind
	Status      TCBStatus
	AdvisoryIDs []string
}

// Error returns the error message.
func (tle *TCBOutOfDateError) Error() string {
	return fmt.Sprintf("%s TCB is not up to date (likely needs upgrade): %s", tle.Kind, tle.Status)
}

// TCBComponent is a TCB component.
type TCBComponent struct {
	SVN      int32  `json:"svn"`
	Category string `json:"category,omitempty"`
	Type     string `json:"type,omitempty"`
}

// TCBLevel is a platform TCB level.
type TCBLevel struct {
	TCB struct {
		PCESVN        uint16           `json:"pcesvn"`
		SGXComponents [16]TCBComponent `json:"sgxtcbcomponents"`
		TDXComponents [16]TCBComponent `json:"tdxtcbcomponents,omitempty"`
	} `json:"tcb"`
	Date        string    `json:"tcbDate"`
	Status      TCBStatus `json:"tcbStatus"`
	AdvisoryIDs []string  `json:"advisoryIDs,omitempty"`
}

// matches performs the SVN comparison.
func (tl *TCBLevel) matches(sgxCompSvn [16]int32, tdxCompSvn *[16]byte, pcesvn uint16) bool {
	// a) Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate (from 01 to
	//    16) with the corresponding values in the TCB Level. If all SGX TCB Comp SVNs in the
	//    certificate are greater or equal to the corresponding values in TCB Level, go to b,
	//    otherwise move to the next item on TCB Levels list.
	for i, comp := range tl.TCB.SGXComponents {
		// At least one SVN is lower, no match.
		if sgxCompSvn[i] < comp.SVN {
			return false
		}
	}

	// b) Compare PCESVN value retrieved from the SGX PCK certificate with the corresponding value
	//    in the TCB Level. If it is greater or equal to the value in TCB Level, read status
	//    assigned to this TCB level (in case of SGX) or go to c (in case of TDX). Otherwise, move
	//    to the next item on TCB Levels list.
	if tl.TCB.PCESVN < pcesvn {
		return false
	}

	if tdxCompSvn != nil {
		// c) Compare SVNs in TEE TCB SVN array retrieved from TD Report in Quote (from index 0 to
		//    15 if TEE TCB SVN at index 1 is set to 0, or from index 2 to 15 otherwise) with the
		//    corresponding values of SVNs in tdxtcbcomponents array of TCB Level. If all TEE TCB
		//    SVNs in the TD Report are greater or equal to the corresponding values in TCB Level,
		//    read tcbStatus assigned to this TCB level. Otherwise, move to the next item on TCB
		//    Levels list.
		var offset int
		if (*tdxCompSvn)[1] != 0 {
			offset = 2
		}

		for i, comp := range tl.TCB.TDXComponents[offset:] {
			// At least one SVN is lower, no match.
			if int32((*tdxCompSvn)[offset+i]) < comp.SVN {
				return false
			}
		}
	}

	// Match.
	return true
}

// TCBStatus is the TCB status.
type TCBStatus int

const (
	statusFieldMissing TCBStatus = iota
	StatusUpToDate
	StatusSWHardeningNeeded
	StatusConfigurationNeeded
	StatusConfigurationAndSWHardeningNeeded
	StatusOutOfDate
	StatusOutOfDateConfigurationNeeded
	StatusRevoked
)

var (
	tcbStatusFwdMap = map[string]TCBStatus{
		"UpToDate":                          StatusUpToDate,
		"SWHardeningNeeded":                 StatusSWHardeningNeeded,
		"ConfigurationNeeded":               StatusConfigurationNeeded,
		"ConfigurationAndSWHardeningNeeded": StatusConfigurationAndSWHardeningNeeded,
		"OutOfDate":                         StatusOutOfDate,
		"OutOfDateConfigurationNeeded":      StatusOutOfDateConfigurationNeeded,
		"Revoked":                           StatusRevoked,
	}
	tcbStatusRevMap = func() map[TCBStatus]string {
		m := make(map[TCBStatus]string)
		for k, v := range tcbStatusFwdMap {
			m[v] = k
		}
		return m
	}()
)

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (s *TCBStatus) UnmarshalText(text []byte) error {
	var ok bool

	*s, ok = tcbStatusFwdMap[string(text)]
	if !ok {
		return fmt.Errorf("pcs/tcb: invalid TCB status: '%v'", string(text))
	}
	return nil
}

// MarshalText implements the encoding.TextMarshaler interface.
func (s *TCBStatus) MarshalText() ([]byte, error) {
	str, ok := tcbStatusRevMap[*s]
	if !ok {
		return nil, fmt.Errorf("pcs/tcb: invalid TCB status: '%v'", int(*s))
	}

	return []byte(str), nil
}

// String returns the string representation of the TCB status.
func (s TCBStatus) String() string {
	return tcbStatusRevMap[s]
}

// SignedQEIdentity is the signed Quoting Enclave identity.
type SignedQEIdentity struct {
	EnclaveIdentity json.RawMessage `cbor:"enclave_identity" json:"enclaveIdentity"`
	Signature       string          `cbor:"signature" json:"signature"`
}

// Open verifies the signature and unmarshals the inner Quoting Enclave identity.
func (sq *SignedQEIdentity) open(teeType TeeType, ts time.Time, policy *QuotePolicy, pk *ecdsa.PublicKey) (*QEIdentity, error) {
	if err := verifyTCBSignature(sq.EnclaveIdentity, sq.Signature, pk); err != nil {
		return nil, err
	}

	var qeIdentity QEIdentity
	if err := json.Unmarshal(sq.EnclaveIdentity, &qeIdentity); err != nil {
		return nil, fmt.Errorf("pcs/tcb: malformed QE identity body: %w", err)
	}
	if err := qeIdentity.validate(teeType, ts, policy); err != nil {
		return nil, err
	}
	return &qeIdentity, nil
}

const (
	qeIDSgx = "QE"
	qeIDTdx = "TD_QE"
)

// QEIdentity is the Quoting Enclave identity.
type QEIdentity struct {
	ID                      string            `json:"id"`
	Version                 int               `json:"version"`
	IssueDate               string            `json:"issueDate"`
	NextUpdate              string            `json:"nextUpdate"`
	TCBEvaluationDataNumber uint32            `json:"tcbEvaluationDataNumber"`
	MiscSelect              string            `json:"miscselect"`
	MiscSelectMask          string            `json:"miscselectMask"`
	Attributes              string            `json:"attributes"`
	AttributesMask          string            `json:"attributesMask"`
	MRSIGNER                string            `json:"mrsigner"`
	ISVProdID               uint16            `json:"isvprodid"`
	TCBLevels               []EnclaveTCBLevel `json:"tcbLevels"`
	AdvisoryIDs             []int             `json:"advisoryIDs,omitempty"`
}

func (qe *QEIdentity) validate(teeType TeeType, ts time.Time, policy *QuotePolicy) error {
	switch teeType {
	case TeeTypeSGX:
		if qe.ID != qeIDSgx {
			return fmt.Errorf("pcs/tcb: unexpected QE identity ID: %s", qe.ID)
		}
	case TeeTypeTDX:
		if qe.ID != qeIDTdx {
			return fmt.Errorf("pcs/tcb: unexpected QE identity ID: %s", qe.ID)
		}
	default:
		return fmt.Errorf("pcs/tcb: unsupported TEE type")
	}
	if qe.Version != requiredQEIdentityVersion {
		return fmt.Errorf("pcs/tcb: unexpected QE identity version: %d", qe.Version)
	}

	// Validate QE identity is not expired/not yet valid based on current time.
	var (
		issueDate time.Time
		err       error
	)
	if issueDate, err = time.Parse(TimestampFormat, qe.IssueDate); err != nil {
		return fmt.Errorf("pcs/tcb: invalid issue date: %w", err)
	}
	if _, err = time.Parse(TimestampFormat, qe.NextUpdate); err != nil {
		return fmt.Errorf("pcs/tcb: invalid next update date: %w", err)
	}

	if issueDate.After(ts) {
		return fmt.Errorf("pcs/tcb: QE identity issue date in the future")
	}
	if ts.Sub(issueDate).Nanoseconds() > int64(policy.TCBValidityPeriod)*24*int64(time.Hour) {
		return fmt.Errorf("pcs/tcb: QE identity expired")
	}

	if qe.TCBEvaluationDataNumber < policy.MinTCBEvaluationDataNumber {
		return fmt.Errorf("pcs/tcb: invalid QE evaluation data number")
	}

	return nil
}

func (qe *QEIdentity) verify(report *SgxReport) error {
	// Verify if MRSIGNER field retrieved from SGX Enclave Report is equal to the value of mrsigner
	// field in QE Identity.
	var expectedMrSigner sgx.MrSigner
	if err := expectedMrSigner.UnmarshalHex(qe.MRSIGNER); err != nil {
		return fmt.Errorf("pcs/tcb: malformed QE MRSIGNER: %w", err)
	}
	if expectedMrSigner != report.mrSigner {
		return fmt.Errorf("pcs/tcb: invalid QE MRSIGNER")
	}

	// Verify if ISVPRODID field retrieved from SGX Enclave Report is equal to the value of
	// isvprodid field in QE Identity.
	if qe.ISVProdID != report.isvProdID {
		return fmt.Errorf("pcs/tcb: invalid QE ISVProdID")
	}

	// Apply miscselectMask (binary mask) from QE Identity to MISCSELECT field retrieved from SGX
	// Enclave Report. Verify if the outcome (miscselectMask & MISCSELECT) is equal to the value of
	// miscselect field in QE Identity.
	rawMiscselect, err := hex.DecodeString(qe.MiscSelect)
	if err != nil {
		return fmt.Errorf("pcs/tcb: malformed miscselect: %w", err)
	}
	if len(rawMiscselect) != 4 {
		return fmt.Errorf("pcs/tcb: malformed miscselect")
	}
	rawMiscselectMask, err := hex.DecodeString(qe.MiscSelectMask)
	if err != nil {
		return fmt.Errorf("pcs/tcb: malformed miscselect mask: %w", err)
	}
	if len(rawMiscselectMask) != 4 {
		return fmt.Errorf("pcs/tcb: malformed miscselect mask")
	}
	expectedMiscselect := binary.LittleEndian.Uint32(rawMiscselect)
	miscselectMask := binary.LittleEndian.Uint32(rawMiscselectMask)
	if report.miscSelect&miscselectMask != expectedMiscselect {
		return fmt.Errorf("pcs/tcb: invalid QE miscselect")
	}

	// Apply attributesMask (binary mask) from QE Identity to ATTRIBUTES field retrieved from SGX
	// Enclave Report. Verify if the outcome (attributesMask & ATTRIBUTES) is equal to the value of
	// attributes field in QE Identity.
	rawAttributes, err := hex.DecodeString(qe.Attributes)
	if err != nil {
		return fmt.Errorf("pcs/tcb: malformed attributes: %w", err)
	}
	if len(rawAttributes) != 16 {
		return fmt.Errorf("pcs/tcb: malformed attributes")
	}
	rawAttributesMask, err := hex.DecodeString(qe.AttributesMask)
	if err != nil {
		return fmt.Errorf("pcs/tcb: malformed attributes mask: %w", err)
	}
	if len(rawAttributesMask) != 16 {
		return fmt.Errorf("pcs/tcb: malformed attributes mask")
	}
	expectedFlags := binary.LittleEndian.Uint64(rawAttributes[:])
	expectedXfrm := binary.LittleEndian.Uint64(rawAttributes[8:])
	flagsMask := binary.LittleEndian.Uint64(rawAttributesMask[:])
	xfrmMask := binary.LittleEndian.Uint64(rawAttributesMask[8:])
	if uint64(report.attributes.Flags)&flagsMask != expectedFlags {
		return fmt.Errorf("pcs/tcb: invalid QE attributes")
	}
	if report.attributes.Xfrm&xfrmMask != expectedXfrm {
		return fmt.Errorf("pcs/tcb: invalid QE attributes")
	}

	// Determine a TCB status of the Quoting Enclave.
	//
	// Go over the list of TCB Levels (descending order) and find the one that has ISVSVN that is
	// lower or equal to the ISVSVN value from SGX Enclave Report.
	var matchedTCBLevel *EnclaveTCBLevel
	for i, tcbLevel := range qe.TCBLevels {
		if tcbLevel.TCB.ISVSVN > report.isvSvn {
			continue
		}
		matchedTCBLevel = &qe.TCBLevels[i]
		break
	}
	if matchedTCBLevel == nil {
		return fmt.Errorf("pcs/tcb: QE TCB level not supported")
	}

	// Ensure QE is up to date.
	if matchedTCBLevel.Status != StatusUpToDate {
		return &TCBOutOfDateError{
			Kind:        TCBKindEnclave,
			Status:      matchedTCBLevel.Status,
			AdvisoryIDs: matchedTCBLevel.AdvisoryIDs,
		}
	}

	return nil
}

// EnclaveTCBLevel is the enclave TCB level.
type EnclaveTCBLevel struct {
	TCB struct {
		ISVSVN uint16 `json:"isvsvn"`
	} `json:"tcb"`
	Date        string    `json:"tcbDate"`
	Status      TCBStatus `json:"tcbStatus"`
	AdvisoryIDs []string  `json:"advisoryIDs"`
}

// SignedTCBEvaluationDataNumbers is the signed TCB evaluation data numbers response body.
type SignedTCBEvaluationDataNumbers struct {
	Numbers   TCBEvaluationDataNumbers `json:"tcbEvaluationDataNumbers"`
	Signature string                   `json:"signature"`
}

// TCBEvaluationDataNumbers is the TCB evaluation data numbers body.
type TCBEvaluationDataNumbers struct {
	ID                    string                    `json:"id"`
	Version               int                       `json:"version"`
	IssueDate             string                    `json:"issueDate"`
	NextUpdate            string                    `json:"nextUpdate"`
	EvaluationDataNumbers []TCBEvaluationDataNumber `json:"tcbEvalNumbers"`
}

// TCBEvaluationDataNumber is the TCB evaluation data number descriptor.
type TCBEvaluationDataNumber struct {
	EvaluationDataNumber uint32 `json:"tcbEvaluationDataNumber"`
	RecoveryEventDate    string `json:"tcbRecoveryEventDate"`
	Date                 string `json:"tcbDate"`
}
