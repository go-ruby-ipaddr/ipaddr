// Copyright (c) the go-ruby-ipaddr/ipaddr authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ipaddr

import "math/big"

// coerceOther mirrors IPAddr#coerce_other: an IPAddr is taken as-is, a string is
// parsed afresh, and anything else (an integer) is built with the receiver's
// family.
func (ip *IPAddr) coerceOther(other any) (*IPAddr, error) {
	switch v := other.(type) {
	case *IPAddr:
		return v, nil
	case string:
		return New(v)
	case *big.Int:
		return NewFromInt(v, ip.family)
	case int:
		return NewFromInt(big.NewInt(int64(v)), ip.family)
	case int64:
		return NewFromInt(big.NewInt(v), ip.family)
	case uint64:
		return NewFromInt(new(big.Int).SetUint64(v), ip.family)
	default:
		return nil, &Error{"cannot coerce IP operand"}
	}
}

// addrMask masks an arbitrary value to the family width, mirroring
// IPAddr#addr_mask.
func (ip *IPAddr) addrMask(addr u128) (u128, error) {
	m, ok := familyMask(ip.family)
	if !ok {
		return u128{}, &AddressFamilyError{"unsupported address family"}
	}
	return addr.and(m), nil
}

// And returns a new IPAddr built by bitwise AND, mirroring IPAddr#&. other may
// be an *IPAddr, a string, an int/int64/uint64 or a *big.Int.
func (ip *IPAddr) And(other any) (*IPAddr, error) {
	o, err := ip.coerceOther(other)
	if err != nil {
		return nil, err
	}
	c := ip.clone()
	if err := c.setU128(ip.addr.and(o.addr)); err != nil {
		return nil, err
	}
	return c, nil
}

// Or returns a new IPAddr built by bitwise OR, mirroring IPAddr#|.
func (ip *IPAddr) Or(other any) (*IPAddr, error) {
	o, err := ip.coerceOther(other)
	if err != nil {
		return nil, err
	}
	c := ip.clone()
	if err := c.setU128(ip.addr.or(o.addr)); err != nil {
		return nil, err
	}
	return c, nil
}

// Not returns a new IPAddr built by bitwise negation (width-masked), mirroring
// IPAddr#~.
func (ip *IPAddr) Not() (*IPAddr, error) {
	c := ip.clone()
	m, err := ip.addrMask(ip.addr.not())
	if err != nil {
		return nil, err
	}
	// addrMask already validated the family, so setU128's width check cannot
	// fail; its error is returned directly to avoid an unreachable branch.
	return c, c.setU128(m)
}

// Xor returns a new IPAddr built by bitwise XOR (width-masked). MRI's IPAddr has
// no ^ operator; this is provided as the natural completion of the bitwise set
// and mirrors the &/| coercion rules.
func (ip *IPAddr) Xor(other any) (*IPAddr, error) {
	o, err := ip.coerceOther(other)
	if err != nil {
		return nil, err
	}
	c := ip.clone()
	m, err := ip.addrMask(ip.addr.xor(o.addr))
	if err != nil {
		return nil, err
	}
	return c, c.setU128(m)
}

// addWithOffset builds a new IPAddr whose address is ip.addr + offset in the same
// family, mirroring the clone.set(@addr + n, @family) idiom of #+/#-/#succ. The
// rare overflow/underflow past the 128-bit space is resolved through big.Int so
// MRI's exact out-of-range "invalid address: <decimal>" message is preserved.
func (ip *IPAddr) addWithOffset(offset int64) (*IPAddr, error) {
	c := ip.clone()
	if v, ok := ip.addr.addOffset(offset); ok {
		if err := c.setU128(v, ip.family); err != nil {
			return nil, err
		}
		return c, nil
	}
	// Overflow/underflow past the 128-bit space is necessarily out of range for
	// the family, so setBig always raises here — matching MRI's set() rejecting
	// @addr + n with the exact out-of-range decimal message.
	return nil, c.setBig(new(big.Int).Add(ip.addr.big(), big.NewInt(offset)), ip.family)
}

// Add returns a new IPAddr greater by offset, mirroring IPAddr#+.
func (ip *IPAddr) Add(offset int64) (*IPAddr, error) { return ip.addWithOffset(offset) }

// Sub returns a new IPAddr less by offset, mirroring IPAddr#-.
func (ip *IPAddr) Sub(offset int64) (*IPAddr, error) { return ip.addWithOffset(-offset) }

// Succ returns the successor address, mirroring IPAddr#succ. As in MRI, the
// successor of the broadcast address raises InvalidAddressError because the
// incremented value overflows the family width.
func (ip *IPAddr) Succ() (*IPAddr, error) { return ip.addWithOffset(1) }

// beginAddr / endAddr mirror the protected helpers of the same name.
func (ip *IPAddr) beginAddr() u128 { return ip.addr.and(ip.mask) }

func (ip *IPAddr) endAddr() u128 {
	full := mask4
	if ip.family == AFInet6 {
		full = mask6
	}
	return ip.addr.or(full.xor(ip.mask))
}

// Include reports whether other is contained in this address's range, mirroring
// IPAddr#include? (aliased as ===). A non-IPAddr operand is coerced; a different
// family yields false rather than an error (a bad coercion is reported as err).
func (ip *IPAddr) Include(other any) (bool, error) {
	o, err := ip.coerceOther(other)
	if err != nil {
		return false, err
	}
	if o.family != ip.family {
		return false, nil
	}
	return ip.beginAddr().cmp(o.beginAddr()) <= 0 && ip.endAddr().cmp(o.endAddr()) >= 0, nil
}

// Eql reports value equality, mirroring IPAddr#==: same family and same integer
// address. A coercion failure yields false (not an error), as MRI's rescue does.
func (ip *IPAddr) Eql(other any) bool {
	o, err := ip.coerceOther(other)
	if err != nil {
		return false
	}
	return ip.family == o.family && ip.addr.cmp(o.addr) == 0
}

// Cmp compares two addresses, mirroring IPAddr#<=> (Comparable). It returns
// (result, true) where result is -1, 0 or 1; ok is false when the operands are
// incomparable (different family or an uncoercible operand), matching MRI's nil.
func (ip *IPAddr) Cmp(other any) (int, bool) {
	o, err := ip.coerceOther(other)
	if err != nil {
		return 0, false
	}
	if o.family != ip.family {
		return 0, false
	}
	return ip.addr.cmp(o.addr), true
}

// Hash returns a hash value used for Hash/Set membership, mirroring IPAddr#hash:
// ([@addr, @mask_addr, @zone_id].hash << 1) | (ipv4? ? 0 : 1). The high bits
// derive from a stable FNV-style mix of the operands; only the parity bit is
// guaranteed to match MRI (the array hash itself is interpreter-specific), so
// Hash is for in-process Set/Hash keying, not cross-runtime equality.
func (ip *IPAddr) Hash() uint64 {
	h := fnv1a64(ip.addr.bytes16())
	h = fnv1a64Cont(h, ip.mask.bytes16())
	h = fnv1a64Cont(h, []byte(ip.zoneID))
	h <<= 1
	if !ip.Ipv4() {
		h |= 1
	}
	return h
}

// bytes16 returns the 16-byte big-endian encoding of the value (endian-safe).
func (v u128) bytes16() []byte {
	b := make([]byte, 16)
	for i := 0; i < 8; i++ {
		b[i] = byte(v.hi >> (56 - 8*i))
		b[8+i] = byte(v.lo >> (56 - 8*i))
	}
	return b
}

const (
	fnvOffset64 = 1469598103934665603
	fnvPrime64  = 1099511628211
)

func fnv1a64(b []byte) uint64 { return fnv1a64Cont(fnvOffset64, b) }
func fnv1a64Cont(h uint64, b []byte) uint64 {
	for _, c := range b {
		h ^= uint64(c)
		h *= fnvPrime64
	}
	return h
}

// ToRange returns the [begin, end] IPAddr pair spanning the network, mirroring
// IPAddr#to_range (each endpoint carries a host mask). Use [IPAddr.Each] to
// iterate the addresses.
func (ip *IPAddr) ToRange() (*IPAddr, *IPAddr, error) {
	lo, err := newFromU128(ip.beginAddr(), ip.family)
	if err != nil {
		return nil, nil, err
	}
	// endAddr is in the same family/width as beginAddr, so this cannot fail once
	// the first succeeded; its error is returned directly.
	hi, err := newFromU128(ip.endAddr(), ip.family)
	return lo, hi, err
}

// newFromU128 builds an IPAddr from a native value already known to be in range,
// the fast internal analogue of NewFromInt used by range/iteration helpers.
func newFromU128(addr u128, family Family) (*IPAddr, error) {
	ip := &IPAddr{}
	if err := ip.setU128(addr, family); err != nil {
		return nil, err
	}
	if family == AFInet {
		ip.mask = mask4
	} else {
		ip.mask = mask6
	}
	return ip, nil
}

// Each iterates every address in the network range, lowest first, invoking fn
// with a host-masked IPAddr for each. MRI's IPAddr has no #each; this is the
// idiomatic Go iteration over to_range that rbgo binds to an each block. fn may
// return an error to stop iteration early.
func (ip *IPAddr) Each(fn func(*IPAddr) error) error {
	lo := ip.beginAddr()
	hi := ip.endAddr()
	for cur := lo; cur.cmp(hi) <= 0; {
		a, err := newFromU128(cur, ip.family)
		if err != nil {
			return err
		}
		if err := fn(a); err != nil {
			return err
		}
		next, ok := cur.addOffset(1)
		if !ok {
			break // reached the top of the address space
		}
		cur = next
	}
	return nil
}
