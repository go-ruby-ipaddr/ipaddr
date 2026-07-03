// Copyright (c) the go-ruby-ipaddr/ipaddr authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ipaddr

// Predicate bit-test constants (mask, value) as fixed-width native values,
// mirroring MRI's IN*MASK-style comparisons.
var (
	v4LoopMask  = hexU128("ff000000")
	v4LoopVal   = hexU128("7f000000")
	v4Priv10M   = hexU128("ff000000")
	v4Priv10V   = hexU128("0a000000")
	v4Priv172M  = hexU128("fff00000")
	v4Priv172V  = hexU128("ac100000")
	v4Priv192M  = hexU128("ffff0000")
	v4Priv192V  = hexU128("c0a80000")
	v4LinkMask  = hexU128("ffff0000")
	v4LinkVal   = hexU128("a9fe0000")
	v4McastMask = hexU128("f0000000")
	v4McastVal  = hexU128("e0000000")

	v6MappedMask = hexU128("ffff00000000")
	v6MappedVal  = hexU128("ffff00000000")
	v6UlaMask    = hexU128("fe000000000000000000000000000000")
	v6UlaVal     = hexU128("fc000000000000000000000000000000")
	v6LinkMask   = hexU128("ffc00000000000000000000000000000")
	v6LinkVal    = hexU128("fe800000000000000000000000000000")
	v6McastMask  = hexU128("ff000000000000000000000000000000")
	v6McastVal   = hexU128("ff000000000000000000000000000000")
	v6One        = u128{0, 1}
	v6FfffLow    = u128{0, 0xffff}
	v6MapMaskAll = hexU128("ffffffffffffffffffffffff00000000")
)

// maskEq reports (addr & m) == v, the bit-test idiom MRI's predicates use.
func (ip *IPAddr) maskEq(m, v u128) bool { return ip.addr.and(m).cmp(v) == 0 }

// Loopback mirrors IPAddr#loopback?. IPv4 127.0.0.0/8, IPv6 ::1, and the
// IPv4-mapped 127.0.0.0/8 are loopback.
func (ip *IPAddr) Loopback() bool {
	switch ip.family {
	case AFInet:
		return ip.maskEq(v4LoopMask, v4LoopVal)
	case AFInet6:
		return ip.addr.cmp(v6One) == 0 ||
			(ip.maskEq(v6MappedMask, v6MappedVal) && ip.maskEq(v4LoopMask, v4LoopVal))
	default:
		return false
	}
}

// Private mirrors IPAddr#private?. IPv4 RFC1918 ranges and IPv6 fc00::/7, plus
// their IPv4-mapped forms.
func (ip *IPAddr) Private() bool {
	switch ip.family {
	case AFInet:
		return ip.maskEq(v4Priv10M, v4Priv10V) ||
			ip.maskEq(v4Priv172M, v4Priv172V) ||
			ip.maskEq(v4Priv192M, v4Priv192V)
	case AFInet6:
		return ip.maskEq(v6UlaMask, v6UlaVal) ||
			(ip.maskEq(v6MappedMask, v6MappedVal) && (ip.maskEq(v4Priv10M, v4Priv10V) ||
				ip.maskEq(v4Priv172M, v4Priv172V) ||
				ip.maskEq(v4Priv192M, v4Priv192V)))
	default:
		return false
	}
}

// LinkLocal mirrors IPAddr#link_local?. IPv4 169.254.0.0/16, IPv6 fe80::/10,
// plus the IPv4-mapped form.
func (ip *IPAddr) LinkLocal() bool {
	switch ip.family {
	case AFInet:
		return ip.maskEq(v4LinkMask, v4LinkVal)
	case AFInet6:
		return ip.maskEq(v6LinkMask, v6LinkVal) ||
			(ip.maskEq(v6MappedMask, v6MappedVal) && ip.maskEq(v4LinkMask, v4LinkVal))
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
		return ip.maskEq(v4McastMask, v4McastVal)
	case AFInet6:
		return ip.maskEq(v6McastMask, v6McastVal)
	default:
		return false
	}
}

// ipv4MappedQ mirrors IPAddr#ipv4_mapped?.
func (ip *IPAddr) ipv4MappedQ() bool {
	return ip.Ipv6() && ip.addr.rsh(32).cmp(v6FfffLow) == 0
}

// ipv4CompatQ mirrors IPAddr#_ipv4_compat?.
func (ip *IPAddr) ipv4CompatQ() bool {
	if !ip.Ipv6() || !ip.addr.rsh(32).isZero() {
		return false
	}
	a := ip.addr.and(mask4)
	return !a.isZero() && a.cmp(v6One) != 0
}

// IsIpv4Mapped is the exported predicate for ipv4_mapped?.
func (ip *IPAddr) IsIpv4Mapped() bool { return ip.ipv4MappedQ() }

// IsIpv4Compat is the exported predicate for ipv4_compat?.
func (ip *IPAddr) IsIpv4Compat() bool { return ip.ipv4CompatQ() }

// Ipv4Mapped converts a native IPv4 address into an IPv4-mapped IPv6 address,
// mirroring IPAddr#ipv4_mapped.
func (ip *IPAddr) Ipv4Mapped() (*IPAddr, error) {
	if !ip.Ipv4() {
		return nil, &InvalidAddressError{"not an IPv4 address: " + ip.addr.big().String()}
	}
	c := ip.clone()
	// The masked value is a valid IPv6 integer by construction, so setU128 cannot
	// fail; its error is provably nil here.
	_ = c.setU128(ip.addr.or(v6MappedVal), AFInet6)
	c.mask = ip.mask.or(v6MapMaskAll)
	return c, nil
}

// Ipv4Compat converts a native IPv4 address into an IPv4-compatible IPv6
// address, mirroring IPAddr#ipv4_compat (obsolete in MRI but reproduced).
func (ip *IPAddr) Ipv4Compat() (*IPAddr, error) {
	if !ip.Ipv4() {
		return nil, &InvalidAddressError{"not an IPv4 address: " + ip.addr.big().String()}
	}
	c := ip.clone()
	// A native IPv4 integer is always a valid IPv6 integer, so setU128 cannot fail.
	_ = c.setU128(ip.addr, AFInet6)
	c.mask = ip.mask.or(v6MapMaskAll)
	return c, nil
}

// Native converts an IPv4-mapped or IPv4-compatible IPv6 address back to native
// IPv4, mirroring IPAddr#native. Any other address is returned unchanged.
func (ip *IPAddr) Native() (*IPAddr, error) {
	if !ip.ipv4MappedQ() && !ip.ipv4CompatQ() {
		return ip, nil
	}
	c := ip.clone()
	return c, c.setU128(ip.addr.and(mask4), AFInet)
}

// Ntop converts a packed network-byte-ordered address (4 or 16 bytes) to its
// readable form, mirroring IPAddr.ntop. A []byte carries no Ruby encoding, so it
// is treated as BINARY (Encoding::ASCII_8BIT): a length other than 4 or 16 raises
// AddressFamilyError, exactly as MRI does for a BINARY-encoded String.
func Ntop(addr []byte) (string, error) {
	switch len(addr) {
	case 4:
		b := make([]byte, 0, 15)
		b = appendDec(b, addr[0])
		b = append(b, '.')
		b = appendDec(b, addr[1])
		b = append(b, '.')
		b = appendDec(b, addr[2])
		b = append(b, '.')
		b = appendDec(b, addr[3])
		return string(b), nil
	case 16:
		b := make([]byte, 0, 39)
		for i := 0; i < 8; i++ {
			if i > 0 {
				b = append(b, ':')
			}
			b = appendHex4(b, uint16(addr[2*i])<<8|uint16(addr[2*i+1]))
		}
		return string(b), nil
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
