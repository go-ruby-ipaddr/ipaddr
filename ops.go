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

// addrMask masks an arbitrary integer to the family width, mirroring
// IPAddr#addr_mask.
func (ip *IPAddr) addrMask(addr *big.Int) (*big.Int, error) {
	switch ip.family {
	case AFInet:
		return new(big.Int).And(addr, in4Mask), nil
	case AFInet6:
		return new(big.Int).And(addr, in6Mask), nil
	default:
		return nil, &AddressFamilyError{"unsupported address family"}
	}
}

// And returns a new IPAddr built by bitwise AND, mirroring IPAddr#&. other may
// be an *IPAddr, a string, an int/int64/uint64 or a *big.Int.
func (ip *IPAddr) And(other any) (*IPAddr, error) {
	o, err := ip.coerceOther(other)
	if err != nil {
		return nil, err
	}
	c := ip.clone()
	if err := c.set(new(big.Int).And(ip.addr, o.addr)); err != nil {
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
	if err := c.set(new(big.Int).Or(ip.addr, o.addr)); err != nil {
		return nil, err
	}
	return c, nil
}

// Not returns a new IPAddr built by bitwise negation (width-masked), mirroring
// IPAddr#~.
func (ip *IPAddr) Not() (*IPAddr, error) {
	c := ip.clone()
	m, err := ip.addrMask(new(big.Int).Not(ip.addr))
	if err != nil {
		return nil, err
	}
	// addrMask already validated the family, so set's width check cannot fail;
	// its error is returned directly to avoid an unreachable branch.
	return c, c.set(m)
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
	m, err := ip.addrMask(new(big.Int).Xor(ip.addr, o.addr))
	if err != nil {
		return nil, err
	}
	return c, c.set(m)
}

// Add returns a new IPAddr greater by offset, mirroring IPAddr#+.
func (ip *IPAddr) Add(offset int64) (*IPAddr, error) {
	c := ip.clone()
	if err := c.set(new(big.Int).Add(ip.addr, big.NewInt(offset)), ip.family); err != nil {
		return nil, err
	}
	return c, nil
}

// Sub returns a new IPAddr less by offset, mirroring IPAddr#-.
func (ip *IPAddr) Sub(offset int64) (*IPAddr, error) {
	c := ip.clone()
	if err := c.set(new(big.Int).Sub(ip.addr, big.NewInt(offset)), ip.family); err != nil {
		return nil, err
	}
	return c, nil
}

// Succ returns the successor address, mirroring IPAddr#succ. As in MRI, the
// successor of the broadcast address raises InvalidAddressError because the
// incremented value overflows the family width.
func (ip *IPAddr) Succ() (*IPAddr, error) {
	c := ip.clone()
	if err := c.set(new(big.Int).Add(ip.addr, big.NewInt(1)), ip.family); err != nil {
		return nil, err
	}
	return c, nil
}

// beginAddr / endAddr mirror the protected helpers of the same name.
func (ip *IPAddr) beginAddr() *big.Int { return new(big.Int).And(ip.addr, ip.mask) }

func (ip *IPAddr) endAddr() *big.Int {
	full := in4Mask
	if ip.family == AFInet6 {
		full = in6Mask
	}
	host := new(big.Int).Xor(full, ip.mask)
	return new(big.Int).Or(ip.addr, host)
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
	return ip.beginAddr().Cmp(o.beginAddr()) <= 0 && ip.endAddr().Cmp(o.endAddr()) >= 0, nil
}

// Eql reports value equality, mirroring IPAddr#==: same family and same integer
// address. A coercion failure yields false (not an error), as MRI's rescue does.
func (ip *IPAddr) Eql(other any) bool {
	o, err := ip.coerceOther(other)
	if err != nil {
		return false
	}
	return ip.family == o.family && ip.addr.Cmp(o.addr) == 0
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
	return ip.addr.Cmp(o.addr), true
}

// Hash returns a hash value used for Hash/Set membership, mirroring IPAddr#hash:
// ([@addr, @mask_addr, @zone_id].hash << 1) | (ipv4? ? 0 : 1). The high bits
// derive from a stable FNV-style mix of the operands; only the parity bit is
// guaranteed to match MRI (the array hash itself is interpreter-specific), so
// Hash is for in-process Set/Hash keying, not cross-runtime equality.
func (ip *IPAddr) Hash() uint64 {
	h := fnv1a64(ip.addr.Bytes())
	h = fnv1a64Cont(h, ip.mask.Bytes())
	h = fnv1a64Cont(h, []byte(ip.zoneID))
	h <<= 1
	if !ip.Ipv4() {
		h |= 1
	}
	return h
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
	lo, err := NewFromInt(ip.beginAddr(), ip.family)
	if err != nil {
		return nil, nil, err
	}
	// endAddr is in the same family/width as beginAddr, so this cannot fail once
	// the first succeeded; its error is returned directly.
	hi, err := NewFromInt(ip.endAddr(), ip.family)
	return lo, hi, err
}

// Each iterates every address in the network range, lowest first, invoking fn
// with a host-masked IPAddr for each. MRI's IPAddr has no #each; this is the
// idiomatic Go iteration over to_range that rbgo binds to an each block. fn may
// return an error to stop iteration early.
func (ip *IPAddr) Each(fn func(*IPAddr) error) error {
	lo := ip.beginAddr()
	hi := ip.endAddr()
	one := big.NewInt(1)
	for cur := new(big.Int).Set(lo); cur.Cmp(hi) <= 0; cur.Add(cur, one) {
		a, err := NewFromInt(cur, ip.family)
		if err != nil {
			return err
		}
		if err := fn(a); err != nil {
			return err
		}
	}
	return nil
}
