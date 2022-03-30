package identity

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
)

func TestLoadOrGenerate(t *testing.T) {
	dataDir, err := ioutil.TempDir("", "oasis-identity-test_")
	require.NoError(t, err, "create data dir")
	defer os.RemoveAll(dataDir)

	factory, err := fileSigner.NewFactory(dataDir, RequiredSignerRoles...)
	require.NoError(t, err, "NewFactory")

	tlsCertPath, _ := TLSCertPaths(dataDir)
	tlsSentryClientCertPath, _ := TLSSentryClientCertPaths(dataDir)

	// Generate a new identity.
	identity, err := LoadOrGenerate(dataDir, factory, true)
	require.NoError(t, err, "LoadOrGenerate")
	require.EqualValues(t, []signature.PublicKey{identity.GetTLSSigner().Public()}, identity.GetTLSPubKeys())
	tlsCertFile1, err := ioutil.ReadFile(tlsCertPath)
	require.NoError(t, err, "read TLS cert")
	tlsSentryClientCertFile1, err := ioutil.ReadFile(tlsSentryClientCertPath)
	require.NoError(t, err, "read sentry client TLS cert")

	// Sleep to make sure that any regenerated TLS certificates will have different expiration.
	time.Sleep(2 * time.Second)

	// Load an existing identity.
	identity2, err := LoadOrGenerate(dataDir, factory, false)
	require.NoError(t, err, "LoadOrGenerate (2)")
	require.EqualValues(t, identity.NodeSigner, identity2.NodeSigner)
	require.EqualValues(t, identity.P2PSigner, identity2.P2PSigner)
	require.EqualValues(t, identity.ConsensusSigner, identity2.ConsensusSigner)
	require.EqualValues(t, identity.VRFSigner, identity2.VRFSigner)
	require.EqualValues(t, identity.GetTLSSigner(), identity2.GetTLSSigner())
	require.NotEqual(t, identity.GetTLSCertificate(), identity2.GetTLSCertificate())
	require.EqualValues(t, identity.GetTLSPubKeys(), identity2.GetTLSPubKeys())
	require.NotEqual(t, identity.TLSSentryClientCertificate, identity2.TLSSentryClientCertificate)
	require.EqualValues(t, identity.TLSSentryClientCertificate.PrivateKey, identity2.TLSSentryClientCertificate.PrivateKey)
	tlsCertFile2, err := ioutil.ReadFile(tlsCertPath)
	require.NoError(t, err, "read TLS cert (2)")
	require.NotEqualValues(t, tlsCertFile1, tlsCertFile2)
	tlsSentryClientCertFile2, err := ioutil.ReadFile(tlsSentryClientCertPath)
	require.NoError(t, err, "read sentry client TLS cert (2)")
	require.NotEqualValues(t, tlsSentryClientCertFile1, tlsSentryClientCertFile2)

	dataDir2, err := ioutil.TempDir("", "oasis-identity-test2_")
	require.NoError(t, err, "create data dir (2)")
	defer os.RemoveAll(dataDir2)

	// Generate a new identity again, this time without persisting TLS certs.
	identity3, err := LoadOrGenerate(dataDir2, factory, false)
	require.NoError(t, err, "LoadOrGenerate (3)")
	require.EqualValues(t, []signature.PublicKey{
		identity3.GetTLSSigner().Public(),
		identity3.GetNextTLSSigner().Public(),
	}, identity3.GetTLSPubKeys())

	// Sleep to make sure that any regenerated TLS certificates will have different expiration.
	time.Sleep(2 * time.Second)

	// Load it back.
	identity4, err := LoadOrGenerate(dataDir2, factory, false)
	require.NoError(t, err, "LoadOrGenerate (4)")
	require.EqualValues(t, identity3.NodeSigner, identity4.NodeSigner)
	require.EqualValues(t, identity3.P2PSigner, identity4.P2PSigner)
	require.EqualValues(t, identity3.ConsensusSigner, identity4.ConsensusSigner)
	require.EqualValues(t, identity3.VRFSigner, identity4.VRFSigner)
	require.NotEqual(t, identity.GetTLSSigner(), identity3.GetTLSSigner())
	require.NotEqual(t, identity2.GetTLSSigner(), identity3.GetTLSSigner())
	require.Equal(t, identity3.GetTLSSigner(), identity4.GetTLSSigner())
	require.NotEqual(t, identity.GetTLSCertificate(), identity3.GetTLSCertificate())
	require.NotEqual(t, identity2.GetTLSCertificate(), identity3.GetTLSCertificate())
	// Private key for identity4 must be the same, but the certificate might be regenerated
	// and different if the wall clock minute changed.
	require.Equal(t, identity3.GetTLSCertificate().PrivateKey, identity4.GetTLSCertificate().PrivateKey)
	require.NotEqual(t, identity3.TLSSentryClientCertificate, identity4.TLSSentryClientCertificate)
	require.EqualValues(t, identity4.TLSSentryClientCertificate.PrivateKey, identity4.TLSSentryClientCertificate.PrivateKey)
}
