// Copyright (c) the go-ruby-ipaddr/ipaddr authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ipaddr

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// toStringRaw mirrors IPAddr#_to_string: the canonical, fully-expanded textual
// form of an arbitrary big integer interpreted in this address's family.
func (ip *IPAddr) toStringRaw(addr *big.Int) string {
	switch ip.family {
	case AFInet:
		b := addr.Bytes()
		buf := make([]byte, 4)
		copy(buf[4-len(b):], b)
		return fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case AFInet6:
		// "%.32x" then a ':' after every 4 hex digits except the last.
		hex := fmt.Sprintf("%032x", addr)
		var sb strings.Builder
		for i := 0; i < 32; i += 4 {
			if i > 0 {
				sb.WriteByte(':')
			}
			sb.WriteString(hex[i : i+4])
		}
		return sb.String()
	default:
		return ""
	}
}

// ToString returns the canonical-form string, mirroring IPAddr#to_string
// (IPv6 is fully expanded, with the zone id appended).
func (ip *IPAddr) ToString() string {
	str := ip.toStringRaw(ip.addr)
	if ip.family == AFInet6 {
		str += ip.zoneID
	}
	return str
}

var (
	reV6LeadingZeros = regexp.MustCompile(`(?i)\b0{1,3}([\da-f]+)\b`)
	reV6Tri          = regexp.MustCompile(`:{3,}`)
	reV6Mapped       = regexp.MustCompile(`(?i)^::(ffff:)?([\da-f]{1,4}):([\da-f]{1,4})$`)
)

// ToS returns the compact, human-readable string, mirroring IPAddr#to_s — IPv4
// dotted-quad, IPv6 with leading zeros stripped and the longest run of zero
// groups collapsed to "::", including the ::a.b.c.d / ::ffff:a.b.c.d forms.
func (ip *IPAddr) ToS() string {
	str := ip.ToString()
	if ip.Ipv4() {
		return str
	}

	str = reV6LeadingZeros.ReplaceAllString(str, "$1")
	// Mirror MRI's ordered sub! cascade collapsing the first run of zero groups.
	for _, pat := range []string{
		`\A0:0:0:0:0:0:0:0\z`,
		`\b0:0:0:0:0:0:0\b`,
		`\b0:0:0:0:0:0\b`,
		`\b0:0:0:0:0\b`,
		`\b0:0:0:0\b`,
		`\b0:0:0\b`,
		`\b0:0\b`,
	} {
		re := regexp.MustCompile(pat)
		if loc := re.FindStringIndex(str); loc != nil {
			repl := ":"
			if strings.HasPrefix(pat, `\A`) {
				repl = "::"
			}
			str = str[:loc[0]] + repl + str[loc[1]:]
			break
		}
	}
	str = reV6Tri.ReplaceAllString(str, "::")

	if m := reV6Mapped.FindStringSubmatch(str); m != nil {
		g2 := parseHex(m[2])
		g3 := parseHex(m[3])
		str = fmt.Sprintf("::%s%d.%d.%d.%d", m[1], g2/256, g2%256, g3/256, g3%256)
	}
	return str
}

func parseHex(s string) int {
	n := new(big.Int)
	n.SetString(s, 16)
	return int(n.Int64())
}

// Cidr returns "address/prefix", mirroring IPAddr#cidr.
func (ip *IPAddr) Cidr() string {
	return fmt.Sprintf("%s/%d", ip.ToS(), ip.Prefix())
}

// Netmask returns the netmask as a string, mirroring IPAddr#netmask.
func (ip *IPAddr) Netmask() string { return ip.toStringRaw(ip.mask) }

// Inspect mirrors IPAddr#inspect: "#<IPAddr: family:address/mask>".
func (ip *IPAddr) Inspect() string {
	var af string
	switch ip.family {
	case AFInet:
		af = "IPv4"
	case AFInet6:
		af = "IPv6"
	default:
		return ""
	}
	zone := ""
	if ip.family == AFInet6 {
		zone = ip.zoneID
	}
	return fmt.Sprintf("#<IPAddr: %s:%s%s/%s>", af, ip.toStringRaw(ip.addr), zone, ip.toStringRaw(ip.mask))
}

// String makes IPAddr satisfy fmt.Stringer, returning the to_s form.
func (ip *IPAddr) String() string { return ip.ToS() }

// HtonString returns the network-byte-ordered packed form, mirroring
// IPAddr#hton (4 bytes for IPv4, 16 for IPv6).
func (ip *IPAddr) HtonString() ([]byte, error) {
	switch ip.family {
	case AFInet:
		b := ip.addr.Bytes()
		buf := make([]byte, 4)
		copy(buf[4-len(b):], b)
		return buf, nil
	case AFInet6:
		b := ip.addr.Bytes()
		buf := make([]byte, 16)
		copy(buf[16-len(b):], b)
		return buf, nil
	default:
		return nil, &AddressFamilyError{"unsupported address family"}
	}
}
