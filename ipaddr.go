// Copyright (c) the go-ruby-ipaddr/ipaddr authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package ipaddr is a pure-Go (no cgo) reimplementation of Ruby's `ipaddr`
// standard library — MRI 4.0.5's IPAddr class. It models an IP address together
// with a netmask (IPv4 or IPv6) and reproduces MRI's parsing, masking, string
// formatting (to_s / to_string / cidr / inspect), set predicates, bitwise
// operators and comparison semantics byte-for-byte.
//
// The arithmetic is carried in math/big.Int so the 128-bit IPv6 space and MRI's
// unbounded-integer behaviour (e.g. the succ overflow check that raises
// "invalid address: 4294967296") are matched exactly, without any dependency on
// a Ruby runtime.
package ipaddr

import (
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// Family is an address family, mirroring the value IPAddr#family returns.
// MRI stores Socket::AF_INET / Socket::AF_INET6 there; this port uses the
// canonical constants below. Compare with [IPAddr.Ipv4]/[IPAddr.Ipv6] for
// family-independent checks.
type Family int

const (
	// AFInet is the IPv4 address family (Socket::AF_INET == 2 on every platform).
	AFInet Family = 2
	// AFInet6 is the IPv6 address family. MRI uses the host's Socket::AF_INET6
	// (which varies: 10 on Linux, 30 on the BSDs/macOS). The exact integer is an
	// implementation detail; use [IPAddr.Ipv6]. We expose Linux's value as the
	// canonical one.
	AFInet6 Family = 10
	// afUnspec mirrors Socket::AF_UNSPEC, the "detect from the string" sentinel.
	afUnspec Family = 0
)

// Error is the base class of every error this package raises, mirroring
// IPAddr::Error < ArgumentError.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// InvalidAddressError mirrors IPAddr::InvalidAddressError.
type InvalidAddressError struct{ Msg string }

func (e *InvalidAddressError) Error() string { return e.Msg }

// InvalidPrefixError mirrors IPAddr::InvalidPrefixError, which in MRI is a
// subclass of InvalidAddressError.
type InvalidPrefixError struct{ Msg string }

func (e *InvalidPrefixError) Error() string { return e.Msg }

// AddressFamilyError mirrors IPAddr::AddressFamilyError.
type AddressFamilyError struct{ Msg string }

func (e *AddressFamilyError) Error() string { return e.Msg }

// Masks, matching IPAddr::IN4MASK / IN6MASK.
var (
	in4Mask = mustHex("ffffffff")
	in6Mask = mustHex("ffffffffffffffffffffffffffffffff")
)

func mustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("ipaddr: bad constant " + s)
	}
	return n
}

var (
	reIPv4 = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	// RE_IPV6ADDRLIKE_FULL: 8 groups, or 6 groups + a dotted-quad tail.
	reIPv6Full = regexp.MustCompile(`(?i)^(?:(?:[\da-f]{1,4}:){7}[\da-f]{1,4}|((?:[\da-f]{1,4}:){6})(\d+)\.(\d+)\.(\d+)\.(\d+))$`)
	// RE_IPV6ADDRLIKE_COMPRESSED: <left>::<right>, right may end in a dotted quad.
	reIPv6Comp = regexp.MustCompile(`(?i)^((?:(?:[\da-f]{1,4}:)*[\da-f]{1,4})?)::((?:((?:[\da-f]{1,4}:)*)(?:[\da-f]{1,4}|(\d+)\.(\d+)\.(\d+)\.(\d+)))?)$`)
)

// IPAddr is a Ruby IPAddr: an address family plus the address and netmask, all
// carried as big integers exactly as MRI does.
type IPAddr struct {
	family Family
	addr   *big.Int
	mask   *big.Int
	zoneID string // includes the leading '%', or "" when absent (IPv6 only)
}

// New parses a human-readable IP address, mirroring IPAddr.new(addr). It accepts
// "address", "address/prefixlen" and "address/netmask"; an IPv6 address may be
// wrapped in square brackets and may carry a %zone suffix. When a prefix or mask
// is given the address is masked. It is the string-argument form of MRI's
// initialize; for the packed-integer form use [NewFromInt].
func New(addr string) (*IPAddr, error) {
	return newImpl(addr, afUnspec)
}

// NewFamily parses like [New] but forces the address family (Socket::AF_INET /
// AF_INET6), raising AddressFamilyError on a mismatch — the two-argument
// IPAddr.new(addr, family) form for string addresses.
func NewFamily(addr string, family Family) (*IPAddr, error) {
	return newImpl(addr, family)
}

// NewFromInt builds an IPAddr from a packed integer address and an explicit
// family, mirroring IPAddr.new(integer, family). family must be AFInet or
// AFInet6.
func NewFromInt(addr *big.Int, family Family) (*IPAddr, error) {
	ip := &IPAddr{}
	switch family {
	case AFInet, AFInet6:
		if err := ip.set(new(big.Int).Set(addr), family); err != nil {
			return nil, err
		}
		if family == AFInet {
			ip.mask = new(big.Int).Set(in4Mask)
		} else {
			ip.mask = new(big.Int).Set(in6Mask)
		}
		return ip, nil
	case afUnspec:
		return nil, &AddressFamilyError{"address family must be specified"}
	default:
		return nil, &AddressFamilyError{fmt.Sprintf("unsupported address family: %d", family)}
	}
}

func newImpl(addr string, family Family) (*IPAddr, error) {
	ip := &IPAddr{}
	prefix, prefixlen, hasPrefix := splitPrefix(addr)

	if m := regexp.MustCompile(`(?i)^\[(.*)\]$`).FindStringSubmatch(prefix); m != nil {
		prefix = m[1]
		family = AFInet6
	}
	if m := regexp.MustCompile(`^(.*)(%\w+)$`).FindStringSubmatch(prefix); m != nil {
		prefix = m[1]
		ip.zoneID = m[2]
		family = AFInet6
	}

	if family == afUnspec || family == AFInet {
		a, err := inAddrChecked(prefix)
		if err != nil {
			return nil, err
		}
		if a != nil {
			ip.addr = a
			ip.family = AFInet
		}
	}
	if ip.addr == nil && (family == afUnspec || family == AFInet6) {
		a, err := in6Addr(prefix)
		if err != nil {
			return nil, err
		}
		ip.addr = a
		ip.family = AFInet6
	}
	if family != afUnspec && ip.family != family {
		return nil, &AddressFamilyError{"address family mismatch"}
	}
	if hasPrefix {
		if err := ip.maskBang(prefixlen); err != nil {
			return nil, err
		}
	} else if ip.family == AFInet {
		ip.mask = new(big.Int).Set(in4Mask)
	} else {
		ip.mask = new(big.Int).Set(in6Mask)
	}
	return ip, nil
}

// splitPrefix splits "addr/prefix" on the first '/', as Ruby's
// addr.split('/', 2) does.
func splitPrefix(s string) (prefix, prefixlen string, has bool) {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// inAddrChecked parses a dotted-quad IPv4 string, mirroring MRI's in_addr. It
// returns (nil, nil) when the string does not match RE_IPV4ADDRLIKE (so the
// caller falls through to IPv6), and surfaces MRI's two error conditions for a
// matched string: an octet >= 256 ("invalid address") and an ambiguous
// zero-filled octet.
func inAddrChecked(addr string) (*big.Int, error) {
	if !reIPv4.MatchString(addr) {
		return nil, nil
	}
	i := big.NewInt(0)
	for _, s := range strings.Split(addr, ".") {
		n, err := strconv.Atoi(s)
		if err != nil || n >= 256 {
			return nil, &InvalidAddressError{"invalid address: " + addr}
		}
		if s != "0" && strings.HasPrefix(s, "0") {
			return nil, &InvalidAddressError{"zero-filled number in IPv4 address is ambiguous: " + addr}
		}
		i.Lsh(i, 8)
		i.Or(i, big.NewInt(int64(n)))
	}
	return i, nil
}

// in6Addr parses an IPv6 string (with an optional embedded IPv4 tail), mirroring
// MRI's in6_addr. A non-matching string raises InvalidAddressError; the message
// uses the (still-nil) @addr, so it renders as "invalid address: ".
func in6Addr(left string) (*big.Int, error) {
	var addr *big.Int
	var right string

	if m := reIPv6Full.FindStringSubmatch(left); m != nil {
		if m[1] != "" { // 6 groups + dotted quad
			v, err := inAddrChecked(strings.Join(m[2:6], "."))
			if err != nil {
				return nil, err
			}
			addr = v
			left = m[1] + ":"
		} else {
			addr = big.NewInt(0)
		}
		right = ""
	} else if m := reIPv6Comp.FindStringSubmatch(left); m != nil {
		full := m[0]
		if m[4] != "" { // compressed with dotted-quad tail
			if strings.Count(full, ":") > 6 {
				return nil, &InvalidAddressError{"invalid address: "}
			}
			v, err := inAddrChecked(strings.Join(m[4:8], "."))
			if err != nil {
				return nil, err
			}
			addr = v
			left = m[1]
			right = m[3] + "0:0"
		} else {
			limit := 8
			if m[1] == "" || m[2] == "" {
				limit = 8
			} else {
				limit = 7
			}
			if strings.Count(full, ":") > limit {
				return nil, &InvalidAddressError{"invalid address: "}
			}
			left = m[1]
			right = m[2]
			addr = big.NewInt(0)
		}
	} else {
		return nil, &InvalidAddressError{"invalid address: "}
	}

	l := splitColons(left)
	r := splitColons(right)
	// The colon-count guards above (and the exact-group full-form regex) ensure
	// len(l)+len(r) never exceeds 8, so rest is non-negative here — MRI keeps a
	// defensive `return nil if rest < 0`, but it is unreachable once the regex
	// has matched and the guards have passed.
	rest := 8 - len(l) - len(r)
	groups := make([]string, 0, 8)
	groups = append(groups, l...)
	for k := 0; k < rest; k++ {
		groups = append(groups, "0")
	}
	groups = append(groups, r...)

	i := big.NewInt(0)
	for _, s := range groups {
		h, _ := strconv.ParseInt(s, 16, 64)
		i.Lsh(i, 16)
		i.Or(i, big.NewInt(h))
	}
	if addr != nil {
		i.Or(i, addr)
	}
	return i, nil
}

// splitColons mirrors Ruby's String#split(':') — empty input yields no elements,
// and a trailing empty field is dropped.
func splitColons(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ":")
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	out := parts[:0]
	for _, p := range parts {
		out = append(out, p)
	}
	return out
}

// set assigns @addr (validating range against the family) and, when family is
// given, switches family and re-clamps an IPv4 mask. Mirrors IPAddr#set.
func (ip *IPAddr) set(addr *big.Int, family ...Family) error {
	fam := ip.family
	if len(family) > 0 && family[0] != afUnspec {
		fam = family[0]
	}
	switch fam {
	case AFInet:
		if addr.Sign() < 0 || addr.Cmp(in4Mask) > 0 {
			return &InvalidAddressError{"invalid address: " + addr.String()}
		}
	case AFInet6:
		if addr.Sign() < 0 || addr.Cmp(in6Mask) > 0 {
			return &InvalidAddressError{"invalid address: " + addr.String()}
		}
	default:
		return &AddressFamilyError{"unsupported address family"}
	}
	ip.addr = addr
	if len(family) > 0 && family[0] != afUnspec {
		ip.family = family[0]
		// MRI clamps an existing IPv4 mask here; when the mask is not yet set
		// (the new-from-integer path) the caller assigns it immediately after.
		if ip.family == AFInet && ip.mask != nil {
			ip.mask = new(big.Int).And(ip.mask, in4Mask)
		}
	}
	return nil
}

// clone makes an independent copy, as Ruby's Object#clone does for these ivars.
func (ip *IPAddr) clone() *IPAddr {
	return &IPAddr{
		family: ip.family,
		addr:   new(big.Int).Set(ip.addr),
		mask:   new(big.Int).Set(ip.mask),
		zoneID: ip.zoneID,
	}
}

// maskBang sets the netmask from a prefix length or netmask string, mirroring
// IPAddr#mask!.
func (ip *IPAddr) maskBang(mask string) error {
	var prefixlen int
	switch {
	case regexp.MustCompile(`^(0|[1-9]+\d*)$`).MatchString(mask):
		prefixlen, _ = strconv.Atoi(mask)
	case regexp.MustCompile(`^\d+$`).MatchString(mask):
		return &InvalidPrefixError{"leading zeros in prefix"}
	default:
		m, err := New(mask)
		if err != nil {
			return err
		}
		if m.family != ip.family {
			return &InvalidPrefixError{"address family is not same"}
		}
		// The netmask value is m.to_i (m.addr). MRI rejects a non-contiguous mask
		// via ((n+1)&n).zero? where n = maskval ^ m's own (full) @mask_addr — i.e.
		// the host part must be a run of trailing ones.
		if !isContiguousMask(m.addr, ip.family) {
			return &InvalidPrefixError{"invalid mask " + mask}
		}
		ip.mask = new(big.Int).Set(m.addr)
		ip.addr.And(ip.addr, ip.mask)
		return nil
	}
	return ip.maskBangLen(prefixlen)
}

// maskBangLen applies an integer prefix length, mirroring the Integer branch of
// IPAddr#mask!.
func (ip *IPAddr) maskBangLen(prefixlen int) error {
	var total int
	var full *big.Int
	switch ip.family {
	case AFInet:
		if prefixlen < 0 || prefixlen > 32 {
			return &InvalidPrefixError{"invalid length"}
		}
		total, full = 32, in4Mask
	case AFInet6:
		if prefixlen < 0 || prefixlen > 128 {
			return &InvalidPrefixError{"invalid length"}
		}
		total, full = 128, in6Mask
	default:
		return &AddressFamilyError{"unsupported address family"}
	}
	masklen := uint(total - prefixlen)
	ip.mask = new(big.Int).Lsh(new(big.Int).Rsh(full, masklen), masklen)
	ip.addr = new(big.Int).Lsh(new(big.Int).Rsh(ip.addr, masklen), masklen)
	return nil
}

// isContiguousMask reports whether m is a left-aligned run of 1s within the
// family's width (a valid netmask), matching MRI's ((n+1)&n).zero? test.
func isContiguousMask(m *big.Int, family Family) bool {
	full := in4Mask
	if family == AFInet6 {
		full = in6Mask
	}
	host := new(big.Int).Xor(full, m) // the inverted (host) part
	plus := new(big.Int).Add(host, big.NewInt(1))
	return new(big.Int).And(plus, host).Sign() == 0
}

// Mask returns a new IPAddr built by masking with the given prefix length or
// netmask string, mirroring IPAddr#mask. Accepts "8", "64", "255.255.255.0", etc.
func (ip *IPAddr) Mask(prefixlen string) (*IPAddr, error) {
	c := ip.clone()
	if err := c.maskBang(prefixlen); err != nil {
		return nil, err
	}
	return c, nil
}

// MaskLen returns a new IPAddr masked to the given integer prefix length.
func (ip *IPAddr) MaskLen(prefixlen int) (*IPAddr, error) {
	c := ip.clone()
	if err := c.maskBangLen(prefixlen); err != nil {
		return nil, err
	}
	return c, nil
}

// Family returns the address family integer, mirroring IPAddr#family.
func (ip *IPAddr) Family() Family { return ip.family }

// ToI returns the integer representation of the address, mirroring IPAddr#to_i.
func (ip *IPAddr) ToI() *big.Int { return new(big.Int).Set(ip.addr) }

// Ipv4 reports whether the address is IPv4, mirroring IPAddr#ipv4?.
func (ip *IPAddr) Ipv4() bool { return ip.family == AFInet }

// Ipv6 reports whether the address is IPv6, mirroring IPAddr#ipv6?.
func (ip *IPAddr) Ipv6() bool { return ip.family == AFInet6 }

// Prefix returns the prefix length in bits, mirroring IPAddr#prefix.
func (ip *IPAddr) Prefix() int {
	var full *big.Int
	var i int
	switch ip.family {
	case AFInet:
		full, i = in4Mask, 32
	case AFInet6:
		full, i = in6Mask, 128
	default:
		return 0
	}
	n := new(big.Int).Xor(full, ip.mask)
	for n.Sign() > 0 {
		n.Rsh(n, 1)
		i--
	}
	return i
}

// SetPrefix sets the prefix length in bits, mirroring IPAddr#prefix=. It mutates
// the receiver (masking the address) and returns it for convenience.
func (ip *IPAddr) SetPrefix(prefix int) (*IPAddr, error) {
	if err := ip.maskBangLen(prefix); err != nil {
		return nil, err
	}
	return ip, nil
}
