package common

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// GuessExternalAddress returns a best guess of the external address,
// or nil if the process fails.
func GuessExternalAddress() net.IP {
	// It is the 21st millennium, for more than three decades, IPv4
	// has sat immobile on the Golden Router of the Internet.  It is
	// the Protocol of Mankind by the will of IETF, and master of a
	// billion addresses by the might of it's inexhaustable legacy
	// systems.  It is a rotting carcass writhing invisibly with
	// power from the Dark Age of Technology.  It is the Carrion
	// Lord of the  Networks for whom a thousand addresses are
	// sacrificed every day, so that it may never truly die.
	//   -- with apologies to Warhammer 40k.
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

// FindAllAddresses returns all addresses found by examining all
// up interfaces (skipping loopback).
func FindAllAddresses() ([]net.IP, error) {
	var addresses []net.IP

	ifaces, ierr := net.Interfaces()
	if ierr != nil {
		return nil, ierr
	}

	for _, iface := range ifaces {
		// Skip interfaces which are down or loopback.
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}

		addrs, aerr := iface.Addrs()
		if aerr != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch a := addr.(type) {
			case *net.IPAddr:
				ip = a.IP
			case *net.IPNet:
				ip = a.IP
			}
			if !ip.IsGlobalUnicast() {
				continue
			}

			if ip != nil {
				addresses = append(addresses, ip)
			}
		}
	}
	return addresses, nil
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

	return nil
}

// GetHostPort makes a normalized "host:port" string from the given raw URL.
func GetHostPort(rawURL string) (string, error) {
	// If the URL is a "host:port" pair already, return it,
	// otherwise url.Parse will choke on it.
	if IsAddrPort(rawURL) == nil {
		return rawURL, nil
	}
	if !strings.Contains(rawURL, "/") {
		_, _, err := net.SplitHostPort(rawURL)
		if err != nil {
			return "", err
		}
		return rawURL, nil
	}

	url, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if url.Path != "" {
		return "", fmt.Errorf("invalid url: %s includes a path", rawURL)
	}

	// Get the port out first, even if not given explicitly.
	port := url.Port()
	if port == "" {
		switch url.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("invalid url %s: no scheme/port", rawURL)
		}
	}

	return net.JoinHostPort(url.Hostname(), port), nil
}
