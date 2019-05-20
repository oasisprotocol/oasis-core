package configparser

import (
	"fmt"
	"net"
	"strconv"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
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

// GetRuntimes parses hex strings to PublicKeys
func GetRuntimes(runtimeIDsHex []string) ([]signature.PublicKey, error) {
	var runtimes []signature.PublicKey
	for _, runtimeHex := range runtimeIDsHex {
		var runtime signature.PublicKey
		if err := runtime.UnmarshalHex(runtimeHex); err != nil {
			return nil, err
		}

		runtimes = append(runtimes, runtime)
	}
	return runtimes, nil
}
