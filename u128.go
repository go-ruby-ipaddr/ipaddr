// Copyright (c) the go-ruby-ipaddr/ipaddr authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ipaddr

import "math/big"

// u128 is a fixed-width 128-bit unsigned integer (hi:lo, big-endian halves). It
// is the native-integer representation the package carries every address and
// netmask in: an IPv4 value lives in the low 32 bits of lo (hi == 0), an IPv6
// value uses the full 128 bits. All arithmetic, masking and comparison run on
// these machine words, so the common IPv4/IPv6 paths never allocate a
// [math/big.Int] — that fixed-width fallback is used only at the arbitrary-
// precision boundary (to_i, the integer constructors and the out-of-range error
// messages), where MRI's unbounded-integer semantics genuinely require it.
//
// The layout is endianness-independent: hi and lo are plain uint64 words and
// every byte-oriented conversion (Hton, Ntop, the big.Int bridge) is written
// with explicit shifts, so the representation behaves identically on little- and
// big-endian targets (verified on s390x under qemu).
type u128 struct {
	hi, lo uint64
}

// Family-width masks, mirroring IPAddr::IN4MASK / IN6MASK.
var (
	mask4 = u128{0, 0xffffffff}
	mask6 = u128{0xffffffffffffffff, 0xffffffffffffffff}
)

// familyMask returns the all-ones mask for the family, or (u128{}, false) for an
// unsupported family.
func familyMask(f Family) (u128, bool) {
	switch f {
	case AFInet:
		return mask4, true
	case AFInet6:
		return mask6, true
	default:
		return u128{}, false
	}
}

func (a u128) and(b u128) u128 { return u128{a.hi & b.hi, a.lo & b.lo} }
func (a u128) or(b u128) u128  { return u128{a.hi | b.hi, a.lo | b.lo} }
func (a u128) xor(b u128) u128 { return u128{a.hi ^ b.hi, a.lo ^ b.lo} }
func (a u128) not() u128       { return u128{^a.hi, ^a.lo} }

func (a u128) isZero() bool { return a.hi == 0 && a.lo == 0 }

// cmp reports -1, 0 or 1 for a<b, a==b, a>b.
func (a u128) cmp(b u128) int {
	if a.hi != b.hi {
		if a.hi < b.hi {
			return -1
		}
		return 1
	}
	if a.lo != b.lo {
		if a.lo < b.lo {
			return -1
		}
		return 1
	}
	return 0
}

// lsh returns a << n for 0 <= n <= 128 (n >= 128 yields zero).
func (a u128) lsh(n uint) u128 {
	switch {
	case n == 0:
		return a
	case n >= 128:
		return u128{}
	case n >= 64:
		return u128{a.lo << (n - 64), 0}
	default:
		return u128{a.hi<<n | a.lo>>(64-n), a.lo << n}
	}
}

// rsh returns a >> n for 0 <= n <= 128 (n >= 128 yields zero).
func (a u128) rsh(n uint) u128 {
	switch {
	case n == 0:
		return a
	case n >= 128:
		return u128{}
	case n >= 64:
		return u128{0, a.hi >> (n - 64)}
	default:
		return u128{a.hi >> n, a.lo>>n | a.hi<<(64-n)}
	}
}

// addOffset returns a + off (off may be negative) together with ok=false when
// the true result falls outside [0, 2^128) — the rare overflow/underflow edge
// that MRI reports as an out-of-range "invalid address" and that this package
// resolves through the big.Int fallback.
func (a u128) addOffset(off int64) (u128, bool) {
	if off >= 0 {
		lo, carry := bits64Add(a.lo, uint64(off))
		hi, c2 := bits64Add(a.hi, carry)
		return u128{hi, lo}, c2 == 0
	}
	// off < 0: subtract its magnitude. -off is safe: for off == math.MinInt64,
	// uint64(off) already holds the magnitude (two's complement wraps to 2^63).
	mag := uint64(-off)
	if off == minInt64 {
		mag = 1 << 63
	}
	lo, borrow := bits64Sub(a.lo, mag)
	hi, b2 := bits64Sub(a.hi, borrow)
	return u128{hi, lo}, b2 == 0
}

const minInt64 = -1 << 63

// bits64Add returns x+y and the carry-out (0 or 1).
func bits64Add(x, y uint64) (sum, carry uint64) {
	sum = x + y
	if sum < x {
		carry = 1
	}
	return
}

// bits64Sub returns x-y and the borrow-out (0 or 1).
func bits64Sub(x, y uint64) (diff, borrow uint64) {
	diff = x - y
	if x < y {
		borrow = 1
	}
	return
}

// big converts to a *big.Int (arbitrary-precision bridge for ToI and error text).
func (v u128) big() *big.Int {
	b := new(big.Int).SetUint64(v.hi)
	b.Lsh(b, 64)
	return b.Or(b, new(big.Int).SetUint64(v.lo))
}

// bigToU128 converts a *big.Int to u128, reporting ok=false when it is negative
// or wider than 128 bits (the caller then raises the family range error, keeping
// MRI's exact decimal message via the original big value).
func bigToU128(b *big.Int) (u128, bool) {
	if b.Sign() < 0 || b.BitLen() > 128 {
		return u128{}, false
	}
	hi := new(big.Int).Rsh(b, 64)
	lo := new(big.Int).Sub(b, new(big.Int).Lsh(hi, 64))
	return u128{hi.Uint64(), lo.Uint64()}, true
}

// hexVal returns the value of a single hex digit, or -1 if c is not one.
func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

// hexU128 parses up to 32 hex digits (big-endian) into a u128, panicking on a
// non-hex byte. Used for the compile-time predicate/mask constants, so a bad
// literal is a programming error — mirroring the old mustHex.
func hexU128(s string) u128 {
	var hi, lo uint64
	for i := 0; i < len(s); i++ {
		d := hexVal(s[i])
		if d < 0 {
			panic("ipaddr: bad constant " + s)
		}
		hi = hi<<4 | lo>>60
		lo = lo<<4 | uint64(d)
	}
	return u128{hi, lo}
}
