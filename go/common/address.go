package common

import (
	"errors"
	"net"
	"strconv"

	"golang.org/x/net/idna"
)

// GuessExternalAddress returns a best guess of the external address,
// or nil if the process fails.
func GuessExternalAddress() net.IP {
	// It is the 21st millenium, for more than three decades, IPv4
	// has sat immobile on the Golden Router of the Internet.  It is
	// the Protocol of Mankind by the will of IETF, and master of a
	// billion addresses by the might of it's inexhaustable legacy
	// systems.  It is a rotting carcass writhing invisibly with
	// power from the Dark Age of Technology.  It is the Carrion
	// Lord of the  Networks for whom a thousand addresses are
	// sacrificed every day, so that it may never truely die.
	//   -- with appologies to Warhammer 40k.
	//
	// Note: This does not actually send any traffic, the use of
	// the AS112=v4 blackhole nameserver is entierely arbitrary,
	// beyond "it is public and in a reserved address block".
	conn, err := net.Dial("udp4", "192.31.196.1:53")
	if err != nil {
		return nil
	}
	defer conn.Close()

	s := conn.LocalAddr().String()
	h, _, err := net.SplitHostPort(s)
	if err != nil {
		return nil
	}

	return net.ParseIP(h)
}

// IsFQDN validates that the provided string is a well-formed FQDN.
func IsFQDN(s string) error {
	_, err := idna.Lookup.ToASCII(s)
	return err
}

// NormalizeFQDN normalizes the provided string as a FQDN.
func NormalizeFQDN(s string) string {
	ret, _ := idna.Registration.ToASCII(s)
	return ret
}

// IsAddrPort validates that the provided string is an address + port.
func IsAddrPort(s string) error {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	if net.ParseIP(h) == nil {
		return errors.New("host is not an IP address")
	}
	if pp, err := strconv.ParseUint(p, 10, 16); err != nil {
		return err
	} else if pp == 0 {
		return errors.New("port is mandatory")
	}

	if len(h) == 0 || len(p) == 0 {
		return errors.New("host and port are both mandatory")
	}

	return nil
}
