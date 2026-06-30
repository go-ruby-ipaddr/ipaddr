// Copyright (c) the go-ruby-ipaddr/ipaddr authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ipaddr

import (
	"fmt"
	"math/big"
)

// maskEq reports (addr & m) == v, the bit-test idiom MRI's predicates use.
func (ip *IPAddr) maskEq(mHex, vHex string) bool {
	m := mustHex(mHex)
	v := mustHex(vHex)
	return new(big.Int).And(ip.addr, m).Cmp(v) == 0
}

// Loopback mirrors IPAddr#loopback?. IPv4 127.0.0.0/8, IPv6 ::1, and the
// IPv4-mapped 127.0.0.0/8 are loopback.
func (ip *IPAddr) Loopback() bool {
	switch ip.family {
	case AFInet:
		return ip.maskEq("ff000000", "7f000000")
	case AFInet6:
		return ip.addr.Cmp(big.NewInt(1)) == 0 ||
			(ip.maskEq("ffff00000000", "ffff00000000") && ip.maskEq("ff000000", "7f000000"))
	default:
		return false
	}
}

// Private mirrors IPAddr#private?. IPv4 RFC1918 ranges and IPv6 fc00::/7, plus
// their IPv4-mapped forms.
func (ip *IPAddr) Private() bool {
	switch ip.family {
	case AFInet:
		return ip.maskEq("ff000000", "0a000000") ||
			ip.maskEq("fff00000", "ac100000") ||
			ip.maskEq("ffff0000", "c0a80000")
	case AFInet6:
		return ip.maskEq("fe000000000000000000000000000000", "fc000000000000000000000000000000") ||
			(ip.maskEq("ffff00000000", "ffff00000000") && (ip.maskEq("ff000000", "0a000000") ||
				ip.maskEq("fff00000", "ac100000") ||
				ip.maskEq("ffff0000", "c0a80000")))
	default:
		return false
	}
}

// LinkLocal mirrors IPAddr#link_local?. IPv4 169.254.0.0/16, IPv6 fe80::/10,
// plus the IPv4-mapped form.
func (ip *IPAddr) LinkLocal() bool {
	switch ip.family {
	case AFInet:
		return ip.maskEq("ffff0000", "a9fe0000")
	case AFInet6:
		return ip.maskEq("ffc00000000000000000000000000000", "fe800000000000000000000000000000") ||
			(ip.maskEq("ffff00000000", "ffff00000000") && ip.maskEq("ffff0000", "a9fe0000"))
	default:
		return false
	}
}

// Multicast reports whether the address is multicast (IPv4 224.0.0.0/4, IPv6
// ff00::/8). MRI 4.0.5's IPAddr has no #multicast?; this is provided for
// completeness and follows the conventional definitions.
func (ip *IPAddr) Multicast() bool {
	switch ip.family {
	case AFInet:
		return ip.maskEq("f0000000", "e0000000")
	case AFInet6:
		return ip.maskEq("ff000000000000000000000000000000", "ff000000000000000000000000000000")
	default:
		return false
	}
}

// Ipv4Mapped reports whether the address is an IPv4-mapped IPv6 address,
// mirroring IPAddr#ipv4_mapped?.
func (ip *IPAddr) ipv4MappedQ() bool {
	return ip.Ipv6() && new(big.Int).Rsh(ip.addr, 32).Cmp(big.NewInt(0xffff)) == 0
}

// ipv4CompatQ mirrors IPAddr#_ipv4_compat?.
func (ip *IPAddr) ipv4CompatQ() bool {
	if !ip.Ipv6() || new(big.Int).Rsh(ip.addr, 32).Sign() != 0 {
		return false
	}
	a := new(big.Int).And(ip.addr, in4Mask)
	return a.Sign() != 0 && a.Cmp(big.NewInt(1)) != 0
}

// IsIpv4Mapped is the exported predicate for ipv4_mapped?.
func (ip *IPAddr) IsIpv4Mapped() bool { return ip.ipv4MappedQ() }

// IsIpv4Compat is the exported predicate for ipv4_compat?.
func (ip *IPAddr) IsIpv4Compat() bool { return ip.ipv4CompatQ() }

// Ipv4Mapped converts a native IPv4 address into an IPv4-mapped IPv6 address,
// mirroring IPAddr#ipv4_mapped.
func (ip *IPAddr) Ipv4Mapped() (*IPAddr, error) {
	if !ip.Ipv4() {
		return nil, &InvalidAddressError{fmt.Sprintf("not an IPv4 address: %s", ip.addr)}
	}
	c := ip.clone()
	// The masked value is a valid IPv6 integer by construction, so set cannot
	// fail; its error is provably nil here.
	_ = c.set(new(big.Int).Or(ip.addr, mustHex("ffff00000000")), AFInet6)
	c.mask = new(big.Int).Or(ip.mask, mustHex("ffffffffffffffffffffffff00000000"))
	return c, nil
}

// Ipv4Compat converts a native IPv4 address into an IPv4-compatible IPv6
// address, mirroring IPAddr#ipv4_compat (obsolete in MRI but reproduced).
func (ip *IPAddr) Ipv4Compat() (*IPAddr, error) {
	if !ip.Ipv4() {
		return nil, &InvalidAddressError{fmt.Sprintf("not an IPv4 address: %s", ip.addr)}
	}
	c := ip.clone()
	// A native IPv4 integer is always a valid IPv6 integer, so set cannot fail.
	_ = c.set(new(big.Int).Set(ip.addr), AFInet6)
	c.mask = new(big.Int).Or(ip.mask, mustHex("ffffffffffffffffffffffff00000000"))
	return c, nil
}

// Native converts an IPv4-mapped or IPv4-compatible IPv6 address back to native
// IPv4, mirroring IPAddr#native. Any other address is returned unchanged.
func (ip *IPAddr) Native() (*IPAddr, error) {
	if !ip.ipv4MappedQ() && !ip.ipv4CompatQ() {
		return ip, nil
	}
	c := ip.clone()
	return c, c.set(new(big.Int).And(ip.addr, in4Mask), AFInet)
}

// Ntop converts a packed network-byte-ordered address (4 or 16 bytes) to its
// readable form, mirroring IPAddr.ntop. A []byte carries no Ruby encoding, so it
// is treated as BINARY (Encoding::ASCII_8BIT): a length other than 4 or 16 raises
// AddressFamilyError, exactly as MRI does for a BINARY-encoded String.
func Ntop(addr []byte) (string, error) {
	switch len(addr) {
	case 4:
		return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]), nil
	case 16:
		groups := make([]any, 8)
		for i := 0; i < 8; i++ {
			groups[i] = uint16(addr[2*i])<<8 | uint16(addr[2*i+1])
		}
		return fmt.Sprintf("%.4x:%.4x:%.4x:%.4x:%.4x:%.4x:%.4x:%.4x", groups...), nil
	default:
		return "", &AddressFamilyError{"unsupported address family"}
	}
}

// NtopString mirrors IPAddr.ntop for a Ruby String argument, honouring MRI's
// encoding precedence: the encoding is checked *before* the byte length.
//
// MRI raises InvalidAddressError "invalid encoding (given <enc>, expected BINARY)"
// for any String whose encoding is not Encoding::ASCII_8BIT/BINARY — and it does
// so even when the length would otherwise be valid (e.g. a 4-byte US-ASCII
// string). Only once the encoding is BINARY does it dispatch on length, raising
// AddressFamilyError for a length other than 4 or 16. encoding is the Ruby
// encoding name of s (e.g. "UTF-8", "US-ASCII", "ASCII-8BIT", "BINARY"); the
// canonical BINARY aliases are "ASCII-8BIT" and "BINARY".
func NtopString(s, encoding string) (string, error) {
	if encoding != "ASCII-8BIT" && encoding != "BINARY" {
		return "", &InvalidAddressError{"invalid encoding (given " + encoding + ", expected BINARY)"}
	}
	return Ntop([]byte(s))
}

// NewNtoh builds an IPAddr from a packed network-byte-ordered address, mirroring
// IPAddr.new_ntoh.
func NewNtoh(addr []byte) (*IPAddr, error) {
	s, err := Ntop(addr)
	if err != nil {
		return nil, err
	}
	return New(s)
}
