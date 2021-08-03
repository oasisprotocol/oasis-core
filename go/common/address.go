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

var reservedRanges = []*net.IPNet{
	// https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
	mustParseCIDRNet("0.0.0.0/8"),          // "This network" [RFC791], Section 3.2
	mustParseCIDRNet("0.0.0.0/32"),         // "This host on this network" [RFC1122], Section 3.2.1.3
	mustParseCIDRNet("10.0.0.0/8"),         // Private-Use [RFC1918]
	mustParseCIDRNet("100.64.0.0/10"),      // Shared Address Space [RFC6598]
	mustParseCIDRNet("169.254.0.0/16"),     // Link Local [RFC3927]
	mustParseCIDRNet("172.16.0.0/12"),      // Private-Use [RFC1918]
	mustParseCIDRNet("192.0.0.0/24"),       // IETF Protocol Assignments [RFC6890],
	mustParseCIDRNet("192.0.0.0/29"),       // IPv4 Service Continuity Prefix [RFC7335]
	mustParseCIDRNet("192.0.0.8/32"),       // IPv4 dummy address [RFC7600]
	mustParseCIDRNet("192.0.0.170/32"),     // NAT64/DNS64 Discovery [RFC8880][RFC7050]
	mustParseCIDRNet("192.0.0.171/32"),     // NAT64/DNS64 Discovery [RFC8880][RFC7050]
	mustParseCIDRNet("192.0.2.0/24"),       // Documentation (TEST-NET-1) [RFC5737]
	mustParseCIDRNet("192.168.0.0/16"),     // Private-Use [RFC1918]
	mustParseCIDRNet("198.18.0.0/15"),      // Benchmarking [RFC2544]
	mustParseCIDRNet("198.51.100.0/24"),    // Documentation (TEST-NET-2) [RFC5737]
	mustParseCIDRNet("203.0.113.0/24"),     // Documentation (TEST-NET-3) [RFC5737]
	mustParseCIDRNet("240.0.0.0/4"),        // Reserved [RFC1112], Section 4
	mustParseCIDRNet("255.255.255.255/32"), // Limited Broadcast [RFC8190] [RFC919]
	mustParseCIDRNet("127.0.0.0/8"),        // Loopback [RFC1122], Section 3.2.1.3

	// https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
	mustParseCIDRNet("::1/128"), // Loopback Address [RFC4291]
	mustParseCIDRNet("::/128"),  // Unspecified Address [RFC4291]
	// mustParseCIDRNet("::ffff:0:0/96"),  // IPv4-mapped Address [RFC4291]
	mustParseCIDRNet("64:ff9b:1::/48"), // IPv4-IPv6 Translat. [RFC8215]
	mustParseCIDRNet("100::/64"),       // Discard-Only Address Block [RFC6666]
	mustParseCIDRNet("2001:2::/48"),    // Benchmarking [RFC5180][RFC Errata 1752]
	mustParseCIDRNet("2001:db8::/32"),  // Documentation [RFC3849]
	mustParseCIDRNet("fe80::/10"),      // Link-Local Unicast [RFC4291]
	mustParseCIDRNet("2001::/23"),      // IETF Protocol Assignments [RFC2928]
	mustParseCIDRNet("fc00::/7"),       // Unique-Local [RFC4193] [RFC8190]
}

// GuessExternalAddress returns a best guess of the external address,
// or nil if the process fails.
func GuessExternalAddress() net.IP {
	// It is the 21st millennium, for more than three decades, IPv4
	// has sat immobile on the Golden Router of the Internet.  It is
	// the Protocol of Mankind by the will of IETF, and master of 4
	// billion addresses by the might of it's inexhaustable legacy
	// systems.  It is a rotting carcass writhing invisibly with
	// power from the Dark Age of Technology.  It is the Carrion
	// Lord of the  Networks for whom a thousand addresses are
	// sacrificed every day, so that it may never truly die.
	//   -- with apologies to Warhammer 40k.
	//
	// Note: This does not actually send any traffic, the use of
	// the AS112=v4 blackhole nameserver is entirely arbitrary,
	// beyond "it is public and in a reserved address block".
	conn, err := net.Dial("udp4", "192.31.196.1:53")
	if err != nil {
		// IPng has gotten significantly more popular since this was
		// initially written, see if that works if IPv4 does not.
		//
		// Like the IPv4 case, this uses BLACKHOLE.AS112.ARPA's
		// address.
		conn, err = net.Dial("udp6", "[2001:4:112::1]:53")
		if err != nil {
			return nil
		}
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

// IsProbablyGloballyReachable returns true if the provided IP address is
// likely to be globally reachable.
func IsProbablyGloballyReachable(ip net.IP) bool {
	for _, ipNet := range reservedRanges {
		if ipNet.Contains(ip) {
			return false
		}
	}

	return true
}

func mustParseCIDRNet(s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic("failed to parse CIDR net: " + err.Error())
	}
	return ipNet
}
