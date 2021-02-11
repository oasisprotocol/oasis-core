package accessctl

import (
	"crypto/x509"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
)

func TestPolicy(t *testing.T) {
	require := require.New(t)

	// Empty policy.
	policy := NewPolicy()
	require.False(policy.IsAllowed("anne", "read"), "Anne should not have read access when policy is empty")

	// Remove nonexisting rule from an empty policy.
	policy.Deny("anne", "write")

	// Adding rules.
	policy.Allow("anne", "read")
	policy.Allow("bob", "write")
	require.True(policy.IsAllowed("anne", "read"), "Anne should have read access")
	require.False(policy.IsAllowed("anne", "write"), "Anne should not have write access")
	require.False(policy.IsAllowed("bob", "read"), "Bob should not have read access")
	require.True(policy.IsAllowed("bob", "write"), "Bob should have write access")

	// Removing rules.
	policy.Deny("anne", "read")
	policy.Deny("bob", "write")
	require.False(policy.IsAllowed("anne", "read"), "Anne should not have read access")
	require.False(policy.IsAllowed("anne", "write"), "Anne should not have write access")
	require.False(policy.IsAllowed("bob", "read"), "Bob should not have read access")
	require.False(policy.IsAllowed("bob", "write"), "Bob should not have write access")

	// Remove nonexisting rule from a non-empty policy.
	policy.Deny("anne", "write")

	// Wildcard rules.
	policy.Allow("anne", "read")
	require.False(policy.IsAllowed("anne", "write"), "Anne should not have write access")
	require.False(policy.IsAllowed("bob", "write"), "Bob should not have write access")
	policy.AllowAll("write")
	require.True(policy.IsAllowed("anne", "write"), "Anne should have write access")
	require.True(policy.IsAllowed("bob", "write"), "Bob should have write access")
	policy.Allow("bob", "write")
	require.True(policy.IsAllowed("bob", "write"), "Bob should have write access")
	policy.Deny(AnySubject, "write")
	require.False(policy.IsAllowed("anne", "write"), "Anne should not have write access")
	require.True(policy.IsAllowed("bob", "write"), "Bob should have write access")
}

func TestSubjectFromCertificate(t *testing.T) {
	require := require.New(t)

	dataDir, err := ioutil.TempDir("", "oasis-storage-grpc-test_")
	require.NoError(err, "Failed to create a temporary directory")
	defer os.RemoveAll(dataDir)

	ident, err := identity.LoadOrGenerate(dataDir, memorySigner.NewFactory(), false)
	require.NoError(err, "Failed to generate a new identity")
	require.Len(ident.GetTLSCertificate().Certificate, 1, "The generated identity contains more than 1 certificate in the chain")

	x509Cert, err := x509.ParseCertificate(ident.GetTLSCertificate().Certificate[0])
	require.NoError(err, "Failed to parse X.509 certificate from TLS certificate")

	sub := SubjectFromX509Certificate(x509Cert)
	require.IsTypef(Subject(""), sub, "Subject %v should of of type Subject")

	policy := NewPolicy()
	policy.Allow(sub, "read")
	require.Truef(policy.IsAllowed(sub, "read"), "Subject %v should have read access", sub)
	require.Falsef(policy.IsAllowed(sub, "write"), "Subject %v should not have write access", sub)
}
