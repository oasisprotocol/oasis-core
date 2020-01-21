package configparser

import (
	tlsPkg "crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/tls"
	"github.com/oasislabs/oasis-core/go/common/node"
)

// ParseAddressList parses addresses.
func ParseAddressList(addresses []string) ([]node.Address, error) {
	var output []node.Address
	for _, rawAddress := range addresses {
		rawIP, rawPort, err := net.SplitHostPort(rawAddress)
		if err != nil {
			return nil, fmt.Errorf("malformed address: %s", err)
		}

		port, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("malformed port: %s", rawPort)
		}

		ip := net.ParseIP(rawIP)
		if ip == nil {
			return nil, fmt.Errorf("malformed ip address: %s", rawIP)
		}

		var address node.Address
		if err := address.FromIP(ip, uint16(port)); err != nil {
			return nil, fmt.Errorf("unknown address family: %s", rawIP)
		}

		output = append(output, address)
	}

	return output, nil
}

// ParseCertificateFiles parses certificate files.
func ParseCertificateFiles(certFiles []string) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(certFiles))
	var err error

	for _, certFile := range certFiles {
		var tlsCert *tlsPkg.Certificate
		tlsCert, err = tls.LoadCertificate(certFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate file %v: %w", certFile, err)
		}
		if len(tlsCert.Certificate) != 1 {
			return nil, fmt.Errorf("certificate file %v should contain exactly 1 certificate in the chain", certFile)
		}
		var x509Cert *x509.Certificate
		x509Cert, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate file %v: %w", certFile, err)
		}
		certs = append(certs, x509Cert)
	}

	return certs, nil
}

// GetRuntimes parses hex strings to PublicKeys
func GetRuntimes(runtimeIDsHex []string) ([]common.Namespace, error) {
	var runtimes []common.Namespace
	for _, runtimeHex := range runtimeIDsHex {
		var runtime common.Namespace
		if err := runtime.UnmarshalHex(runtimeHex); err != nil {
			return nil, err
		}

		runtimes = append(runtimes, runtime)
	}
	return runtimes, nil
}
