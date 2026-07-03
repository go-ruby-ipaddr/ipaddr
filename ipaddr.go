// Copyright (c) the go-ruby-ipaddr/ipaddr authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package ipaddr is a pure-Go (no cgo) reimplementation of Ruby's `ipaddr`
// standard library — MRI 4.0.5's IPAddr class. It models an IP address together
// with a netmask (IPv4 or IPv6) and reproduces MRI's parsing, masking, string
// formatting (to_s / to_string / cidr / inspect), set predicates, bitwise
// operators and comparison semantics byte-for-byte.
//
// Addresses and netmasks are carried in a fixed-width native-integer
// representation (see [u128]): IPv4 in 32 bits, IPv6 in 128, with masks,
// arithmetic and comparisons done in machine words so the common paths never
// allocate. MRI's unbounded-integer edges — the succ/`+` overflow that raises
// "invalid address: 4294967296", the packed-integer constructors and #to_i —
// are handled through a [math/big.Int] bridge used only where arbitrary
// precision is genuinely required. The representation is endianness-independent.
package ipaddr

import (
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

var (
	reIPv4 = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	// RE_IPV6ADDRLIKE_FULL: 8 groups, or 6 groups + a dotted-quad tail. Retained
	// for the embedded-IPv4 / dotted-quad fallback that [in6Fast] declines.
	reIPv6Full = regexp.MustCompile(`(?i)^(?:(?:[\da-f]{1,4}:){7}[\da-f]{1,4}|((?:[\da-f]{1,4}:){6})(\d+)\.(\d+)\.(\d+)\.(\d+))$`)
	// RE_IPV6ADDRLIKE_COMPRESSED: <left>::<right>, right may end in a dotted quad.
	reIPv6Comp = regexp.MustCompile(`(?i)^((?:(?:[\da-f]{1,4}:)*[\da-f]{1,4})?)::((?:((?:[\da-f]{1,4}:)*)(?:[\da-f]{1,4}|(\d+)\.(\d+)\.(\d+)\.(\d+)))?)$`)
)

// IPAddr is a Ruby IPAddr: an address family plus the address and netmask, all
// carried in the fixed-width native-integer representation [u128].
type IPAddr struct {
	family Family
	addr   u128
	mask   u128
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
		if err := ip.setBig(addr, family); err != nil {
			return nil, err
		}
		if family == AFInet {
			ip.mask = mask4
		} else {
			ip.mask = mask6
		}
		return ip, nil
	case afUnspec:
		return nil, &AddressFamilyError{"address family must be specified"}
	default:
		return nil, &AddressFamilyError{"unsupported address family: " + strconv.Itoa(int(family))}
	}
}

func newImpl(addr string, family Family) (*IPAddr, error) {
	ip := &IPAddr{}
	prefix, prefixlen, hasPrefix := splitPrefix(addr)

	// [ipv6] bracket form: strip and force the IPv6 family.
	if len(prefix) >= 2 && prefix[0] == '[' && prefix[len(prefix)-1] == ']' {
		prefix = prefix[1 : len(prefix)-1]
		family = AFInet6
	}
	// %zone suffix (IPv6 only): the trailing run of word characters after the
	// last '%', mirroring MRI's /^(.*)(%\w+)$/.
	if z := zoneSplit(prefix); z >= 0 {
		ip.zoneID = prefix[z:]
		prefix = prefix[:z]
		family = AFInet6
	}

	if family == afUnspec || family == AFInet {
		a, matched, err := inAddrParse(prefix)
		if err != nil {
			return nil, err
		}
		if matched {
			ip.addr = u128{0, uint64(a)}
			ip.family = AFInet
		}
	}
	if ip.family != AFInet && (family == afUnspec || family == AFInet6) {
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
		ip.mask = mask4
	} else {
		ip.mask = mask6
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

// zoneSplit returns the byte index where a %zone suffix begins (so s[:z] is the
// address and s[z:] is "%zone", leading '%' included), or -1 when there is none.
// It mirrors MRI's /^(.*)(%\w+)$/: the suffix is the last '%' followed by one or
// more word characters ([0-9A-Za-z_]) running to the end of the string.
func zoneSplit(s string) int {
	i := strings.LastIndexByte(s, '%')
	if i < 0 || i == len(s)-1 {
		return -1
	}
	for j := i + 1; j < len(s); j++ {
		if !isWord(s[j]) {
			return -1
		}
	}
	return i
}

func isWord(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// inAddrParse parses a dotted-quad IPv4 string without regexp or big.Int,
// mirroring MRI's in_addr. matched is false (with a nil error) when the string
// is not four dot-separated all-digit fields, so the caller falls through to
// IPv6; a matched string surfaces MRI's two error conditions in order — an octet
// >= 256 ("invalid address") then an ambiguous zero-filled octet.
func inAddrParse(addr string) (val uint32, matched bool, err error) {
	var acc uint32
	field, start := 0, 0
	for i := 0; i <= len(addr); i++ {
		if i < len(addr) && addr[i] != '.' {
			continue
		}
		seg := addr[start:i]
		start = i + 1
		if field == 4 || len(seg) == 0 {
			return 0, false, nil // not four non-empty fields -> not IPv4-like
		}
		n := 0
		for j := 0; j < len(seg); j++ {
			c := seg[j]
			if c < '0' || c > '9' {
				return 0, false, nil // a non-digit -> not IPv4-like
			}
			if len(seg) <= 3 {
				n = n*10 + int(c-'0')
			}
		}
		// A field of >3 digits is necessarily >= 256; only <=3-digit fields are
		// value-checked exactly. Message uses the whole address, as MRI does.
		if len(seg) > 3 || n >= 256 {
			return 0, false, &InvalidAddressError{"invalid address: " + addr}
		}
		if seg != "0" && seg[0] == '0' {
			return 0, false, &InvalidAddressError{"zero-filled number in IPv4 address is ambiguous: " + addr}
		}
		acc = acc<<8 | uint32(n)
		field++
	}
	if field != 4 {
		return 0, false, nil
	}
	return acc, true, nil
}

// in6Addr parses an IPv6 string into a u128, mirroring MRI's in6_addr. The
// common colon-hextet forms are handled by the allocation-light [in6Fast]; any
// form it declines (embedded IPv4, or an input it cannot certify) falls back to
// the regexp-driven [in6Regex], which reproduces MRI's exact error semantics.
func in6Addr(left string) (u128, error) {
	if v, ok := in6Fast(left); ok {
		return v, nil
	}
	return in6Regex(left)
}

// in6Fast parses the standard colon-separated hextet forms (full 8-group and
// single "::" compressed) with no regexp and no allocation of a big.Int. It
// returns ok=false — deferring to the regexp path — for anything it does not
// certify as valid, including every invalid input and every embedded-IPv4 form,
// so MRI's error messages and dotted-quad handling are preserved unchanged.
func in6Fast(s string) (u128, bool) {
	if strings.IndexByte(s, '.') >= 0 {
		return u128{}, false // embedded IPv4 -> regexp path
	}
	if s == "::" {
		// The all-zeros form is rare (not on any hot path); route it through the
		// faithful regexp parser so that non-embedded-compressed path stays
		// exercised as the safety net for every other compressed input.
		return u128{}, false
	}
	if i := strings.Index(s, "::"); i >= 0 {
		// Exactly one "::" is allowed, and the right side may not abut a third
		// colon. (The left side cannot: strings.Index found the first "::", so the
		// byte before it is never a colon.)
		rest := s[i+2:]
		if strings.Contains(rest, "::") || (len(rest) > 0 && rest[0] == ':') {
			return u128{}, false
		}
		lg, lok := parseHextets(s[:i])
		rg, rok := parseHextets(rest)
		if !lok || !rok || len(lg)+len(rg) > 7 {
			// >7 groups leaves no room for the "::" zero run -> invalid; defer.
			return u128{}, false
		}
		var g [8]uint16
		copy(g[:], lg)
		copy(g[8-len(rg):], rg)
		return groupsToU128(g), true
	}
	// No "::": must be exactly eight hextets.
	gs, ok := parseHextets(s)
	if !ok || len(gs) != 8 {
		return u128{}, false
	}
	var g [8]uint16
	copy(g[:], gs)
	return groupsToU128(g), true
}

// parseHextets splits a colon-separated list of 1-4 digit hex groups. The empty
// string yields zero groups; any empty or over-long or non-hex group makes it
// report ok=false.
func parseHextets(s string) ([]uint16, bool) {
	if s == "" {
		return nil, true
	}
	out := make([]uint16, 0, 8)
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != ':' {
			continue
		}
		seg := s[start:i]
		start = i + 1
		if len(seg) < 1 || len(seg) > 4 {
			return nil, false
		}
		var v uint16
		for j := 0; j < len(seg); j++ {
			d := hexVal(seg[j])
			if d < 0 {
				return nil, false
			}
			v = v<<4 | uint16(d)
		}
		out = append(out, v)
	}
	return out, true
}

// groupsToU128 packs eight big-endian hextets into a u128.
func groupsToU128(g [8]uint16) u128 {
	hi := uint64(g[0])<<48 | uint64(g[1])<<32 | uint64(g[2])<<16 | uint64(g[3])
	lo := uint64(g[4])<<48 | uint64(g[5])<<32 | uint64(g[6])<<16 | uint64(g[7])
	return u128{hi, lo}
}

// in6Regex is the regexp-driven IPv6 parser, a faithful transcription of MRI's
// in6_addr including the two embedded-dotted-quad forms and the colon-count
// guards. A non-matching string raises InvalidAddressError; the message uses the
// (still-nil) @addr, so it renders as "invalid address: ".
func in6Regex(left string) (u128, error) {
	var embedded u128
	var haveEmbedded bool
	var right string

	if m := reIPv6Full.FindStringSubmatch(left); m != nil {
		if m[1] != "" { // 6 groups + dotted quad
			// The regex already captured four \d+ groups, so inAddrParse always
			// matches here; only its range/ambiguity error can fire.
			v, _, err := inAddrParse(strings.Join(m[2:6], "."))
			if err != nil {
				return u128{}, err
			}
			embedded, haveEmbedded = u128{0, uint64(v)}, true
			left = m[1] + ":"
		}
		right = ""
	} else if m := reIPv6Comp.FindStringSubmatch(left); m != nil {
		full := m[0]
		if m[4] != "" { // compressed with dotted-quad tail
			if strings.Count(full, ":") > 6 {
				return u128{}, &InvalidAddressError{"invalid address: "}
			}
			v, _, err := inAddrParse(strings.Join(m[4:8], "."))
			if err != nil {
				return u128{}, err
			}
			embedded, haveEmbedded = u128{0, uint64(v)}, true
			left = m[1]
			right = m[3] + "0:0"
		} else {
			limit := 8
			if m[1] != "" && m[2] != "" {
				limit = 7
			}
			if strings.Count(full, ":") > limit {
				return u128{}, &InvalidAddressError{"invalid address: "}
			}
			left = m[1]
			right = m[2]
		}
	} else {
		return u128{}, &InvalidAddressError{"invalid address: "}
	}

	l := splitColons(left)
	r := splitColons(right)
	// The colon-count guards (and the exact-group full-form regex) ensure
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

	var v u128
	for _, s := range groups {
		h, _ := strconv.ParseUint(s, 16, 32)
		v = v.lsh(16).or(u128{0, h})
	}
	if haveEmbedded {
		v = v.or(embedded)
	}
	return v, nil
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

// setU128 assigns @addr (validating range against the family) and, when family
// is given, switches family and re-clamps an IPv4 mask. Mirrors IPAddr#set.
func (ip *IPAddr) setU128(addr u128, family ...Family) error {
	fam := ip.family
	if len(family) > 0 && family[0] != afUnspec {
		fam = family[0]
	}
	m, ok := familyMask(fam)
	if !ok {
		return &AddressFamilyError{"unsupported address family"}
	}
	if addr.cmp(m) > 0 {
		return &InvalidAddressError{"invalid address: " + addr.big().String()}
	}
	ip.addr = addr
	if len(family) > 0 && family[0] != afUnspec {
		ip.family = family[0]
		// MRI clamps an existing IPv4 mask here; when the mask has not yet been
		// assigned it is the zero value and the clamp is a harmless no-op (the
		// new-from-integer path assigns the real mask immediately after).
		if ip.family == AFInet {
			ip.mask = ip.mask.and(mask4)
		}
	}
	return nil
}

// setBig assigns @addr from a *big.Int, the arbitrary-precision entry used by
// the integer constructors and coercions. A value that is negative or wider than
// the family width raises InvalidAddressError with MRI's exact decimal message.
func (ip *IPAddr) setBig(addr *big.Int, family ...Family) error {
	v, ok := bigToU128(addr)
	if !ok {
		return &InvalidAddressError{"invalid address: " + addr.String()}
	}
	return ip.setU128(v, family...)
}

// clone makes an independent copy, as Ruby's Object#clone does for these ivars.
func (ip *IPAddr) clone() *IPAddr {
	c := *ip
	return &c
}

// maskBang sets the netmask from a prefix length or netmask string, mirroring
// IPAddr#mask!.
func (ip *IPAddr) maskBang(mask string) error {
	prefixlen, isPrefix, leadingZero, allDigits := classifyPrefix(mask)
	switch {
	case isPrefix:
		return ip.maskBangLen(prefixlen)
	case leadingZero:
		return &InvalidPrefixError{"leading zeros in prefix"}
	default:
		_ = allDigits
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
		ip.mask = m.addr
		ip.addr = ip.addr.and(ip.mask)
		return nil
	}
}

// classifyPrefix categorises a string mask without regexp, mirroring MRI's
// /\A(0|[1-9]+\d*)\z/ (a prefix length) and /\A\d+\z/ (all-digit with a leading
// zero -> "leading zeros in prefix") cases; anything else is a netmask string.
// A prefix length that overflows int is reported large enough to fail the
// subsequent range check, matching MRI's unbounded to_i.
func classifyPrefix(mask string) (prefixlen int, isPrefix, leadingZero, allDigits bool) {
	if mask == "" {
		return 0, false, false, false
	}
	for i := 0; i < len(mask); i++ {
		if mask[i] < '0' || mask[i] > '9' {
			return 0, false, false, false
		}
	}
	allDigits = true
	if mask != "0" && mask[0] == '0' {
		return 0, false, true, true
	}
	n, err := strconv.Atoi(mask)
	if err != nil {
		n = 1 << 30 // out-of-range decimal: certainly > 128, fails range check
	}
	return n, true, false, true
}

// maskBangLen applies an integer prefix length, mirroring the Integer branch of
// IPAddr#mask!.
func (ip *IPAddr) maskBangLen(prefixlen int) error {
	var total int
	var full u128
	switch ip.family {
	case AFInet:
		if prefixlen < 0 || prefixlen > 32 {
			return &InvalidPrefixError{"invalid length"}
		}
		total, full = 32, mask4
	case AFInet6:
		if prefixlen < 0 || prefixlen > 128 {
			return &InvalidPrefixError{"invalid length"}
		}
		total, full = 128, mask6
	default:
		return &AddressFamilyError{"unsupported address family"}
	}
	masklen := uint(total - prefixlen)
	ip.mask = full.rsh(masklen).lsh(masklen)
	ip.addr = ip.addr.rsh(masklen).lsh(masklen)
	return nil
}

// isContiguousMask reports whether m is a left-aligned run of 1s within the
// family's width (a valid netmask), matching MRI's ((n+1)&n).zero? test.
func isContiguousMask(m u128, family Family) bool {
	full, ok := familyMask(family)
	if !ok {
		return false
	}
	host := full.xor(m) // the inverted (host) part
	plus, _ := host.addOffset(1)
	return plus.and(host).isZero()
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
func (ip *IPAddr) ToI() *big.Int { return ip.addr.big() }

// Ipv4 reports whether the address is IPv4, mirroring IPAddr#ipv4?.
func (ip *IPAddr) Ipv4() bool { return ip.family == AFInet }

// Ipv6 reports whether the address is IPv6, mirroring IPAddr#ipv6?.
func (ip *IPAddr) Ipv6() bool { return ip.family == AFInet6 }

// Prefix returns the prefix length in bits, mirroring IPAddr#prefix.
func (ip *IPAddr) Prefix() int {
	full, ok := familyMask(ip.family)
	if !ok {
		return 0
	}
	i := 128
	if ip.family == AFInet {
		i = 32
	}
	n := full.xor(ip.mask)
	for !n.isZero() {
		n = n.rsh(1)
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
