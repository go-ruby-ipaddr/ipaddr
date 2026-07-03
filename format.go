// Copyright (c) the go-ruby-ipaddr/ipaddr authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ipaddr

import "strconv"

const hexDigit = "0123456789abcdef"

// hextets unpacks the 128-bit value into its eight big-endian 16-bit groups.
func (v u128) hextets() [8]uint16 {
	return [8]uint16{
		uint16(v.hi >> 48), uint16(v.hi >> 32), uint16(v.hi >> 16), uint16(v.hi),
		uint16(v.lo >> 48), uint16(v.lo >> 32), uint16(v.lo >> 16), uint16(v.lo),
	}
}

// appendHex4 appends v as exactly four lowercase hex digits (the expanded form).
func appendHex4(b []byte, v uint16) []byte {
	return append(b, hexDigit[v>>12&0xf], hexDigit[v>>8&0xf], hexDigit[v>>4&0xf], hexDigit[v&0xf])
}

// appendHex appends v as lowercase hex with no leading zeros (MRI's per-group
// leading-zero strip), emitting "0" for a zero group.
func appendHex(b []byte, v uint16) []byte {
	if v == 0 {
		return append(b, '0')
	}
	var tmp [4]byte
	i := 4
	for v > 0 {
		i--
		tmp[i] = hexDigit[v&0xf]
		v >>= 4
	}
	return append(b, tmp[i:]...)
}

// appendDec appends a byte value 0..255 as decimal.
func appendDec(b []byte, v uint8) []byte {
	if v >= 100 {
		b = append(b, hexDigit[v/100])
		v %= 100
		b = append(b, hexDigit[v/10], hexDigit[v%10])
	} else if v >= 10 {
		b = append(b, hexDigit[v/10], hexDigit[v%10])
	} else {
		b = append(b, hexDigit[v])
	}
	return b
}

// toStringRaw mirrors IPAddr#_to_string: the canonical, fully-expanded textual
// form of an arbitrary value interpreted in this address's family (IPv4 dotted
// quad, IPv6 as eight zero-padded hextets).
func (ip *IPAddr) toStringRaw(addr u128) string {
	switch ip.family {
	case AFInet:
		lo := uint32(addr.lo)
		b := make([]byte, 0, 15)
		b = appendDec(b, uint8(lo>>24))
		b = append(b, '.')
		b = appendDec(b, uint8(lo>>16))
		b = append(b, '.')
		b = appendDec(b, uint8(lo>>8))
		b = append(b, '.')
		b = appendDec(b, uint8(lo))
		return string(b)
	case AFInet6:
		h := addr.hextets()
		b := make([]byte, 0, 39)
		for i := 0; i < 8; i++ {
			if i > 0 {
				b = append(b, ':')
			}
			b = appendHex4(b, h[i])
		}
		return string(b)
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

// ToS returns the compact, human-readable string, mirroring IPAddr#to_s — IPv4
// dotted-quad, IPv6 with leading zeros stripped and the longest run of zero
// groups collapsed to "::" (RFC 5952, byte-identical to MRI), including the
// ::a.b.c.d / ::ffff:a.b.c.d embedded-IPv4 forms. The zero-collapse is a direct
// scan over the eight hextets — no regexp.
func (ip *IPAddr) ToS() string {
	if ip.Ipv4() {
		return ip.toStringRaw(ip.addr)
	}
	h := ip.addr.hextets()

	// MRI applies the embedded-IPv4 rewrite only when the compressed string ends
	// exactly at the "::(ffff:)?X:Y" tail; a %zone suffix defeats that anchor, so
	// the rewrite is suppressed whenever a zone id is present.
	if ip.zoneID == "" {
		if h[0] == 0 && h[1] == 0 && h[2] == 0 && h[3] == 0 && h[4] == 0 && h[5] == 0xffff {
			return "::ffff:" + dottedQuad(h[6], h[7])
		}
		if h[0] == 0 && h[1] == 0 && h[2] == 0 && h[3] == 0 && h[4] == 0 && h[5] == 0 && h[6] != 0 {
			return "::" + dottedQuad(h[6], h[7])
		}
	} else if ip.addr.isZero() {
		// The all-zeros "::" collapse is MRI's only anchored, whole-string pattern
		// (\A0:0:0:0:0:0:0:0\z); a %zone suffix defeats that anchor, so only the
		// leading seven zero groups collapse, leaving a trailing "0" -> "::0%zone".
		return "::0" + ip.zoneID
	}

	b := make([]byte, 0, 45)
	b = appendCompressedV6(b, h)
	if ip.zoneID != "" {
		b = append(b, ip.zoneID...)
	}
	return string(b)
}

// dottedQuad renders two hextets as a dotted-quad tail, as MRI's to_s rewrite
// does (sprintf '%d.%d.%d.%d' from the high/low bytes of each group).
func dottedQuad(x, y uint16) string {
	b := make([]byte, 0, 15)
	b = appendDec(b, uint8(x>>8))
	b = append(b, '.')
	b = appendDec(b, uint8(x))
	b = append(b, '.')
	b = appendDec(b, uint8(y>>8))
	b = append(b, '.')
	b = appendDec(b, uint8(y))
	return string(b)
}

// appendCompressedV6 writes the hextets with the leftmost-longest run of zero
// groups (length >= 2) collapsed to "::", matching MRI's ordered sub! cascade.
func appendCompressedV6(b []byte, h [8]uint16) []byte {
	start, length := longestZeroRun(h)
	if length < 2 {
		for i := 0; i < 8; i++ {
			if i > 0 {
				b = append(b, ':')
			}
			b = appendHex(b, h[i])
		}
		return b
	}
	for i := 0; i < start; i++ {
		if i > 0 {
			b = append(b, ':')
		}
		b = appendHex(b, h[i])
	}
	b = append(b, ':', ':')
	for i := start + length; i < 8; i++ {
		b = appendHex(b, h[i])
		if i < 7 {
			b = append(b, ':')
		}
	}
	return b
}

// longestZeroRun returns the start index and length of the leftmost longest run
// of consecutive zero hextets (length 0 when there are none).
func longestZeroRun(h [8]uint16) (start, length int) {
	start, length = -1, 0
	for i := 0; i < 8; {
		if h[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && h[j] == 0 {
			j++
		}
		if j-i > length {
			start, length = i, j-i
		}
		i = j
	}
	return
}

// Cidr returns "address/prefix", mirroring IPAddr#cidr.
func (ip *IPAddr) Cidr() string {
	return ip.ToS() + "/" + strconv.Itoa(ip.Prefix())
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
	return "#<IPAddr: " + af + ":" + ip.toStringRaw(ip.addr) + zone + "/" + ip.toStringRaw(ip.mask) + ">"
}

// String makes IPAddr satisfy fmt.Stringer, returning the to_s form.
func (ip *IPAddr) String() string { return ip.ToS() }

// HtonString returns the network-byte-ordered packed form, mirroring
// IPAddr#hton (4 bytes for IPv4, 16 for IPv6). The byte order is written with
// explicit shifts, so it is identical on little- and big-endian hosts.
func (ip *IPAddr) HtonString() ([]byte, error) {
	switch ip.family {
	case AFInet:
		lo := uint32(ip.addr.lo)
		return []byte{byte(lo >> 24), byte(lo >> 16), byte(lo >> 8), byte(lo)}, nil
	case AFInet6:
		buf := make([]byte, 16)
		for i := 0; i < 8; i++ {
			buf[i] = byte(ip.addr.hi >> (56 - 8*i))
			buf[8+i] = byte(ip.addr.lo >> (56 - 8*i))
		}
		return buf, nil
	default:
		return nil, &AddressFamilyError{"unsupported address family"}
	}
}
