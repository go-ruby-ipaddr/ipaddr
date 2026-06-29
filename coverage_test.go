// Copyright (c) the go-ruby-ipaddr/ipaddr authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ipaddr

import (
	"errors"
	"math/big"
	"testing"
)

// badFamily fabricates an IPAddr carrying an unsupported family so the defensive
// "unsupported address family" branches — which mirror MRI's
// `raise AddressFamilyError` guards but are unreachable through the public
// constructors — are exercised.
func badFamily() *IPAddr {
	return &IPAddr{family: Family(99), addr: big.NewInt(1), mask: big.NewInt(1)}
}

// TestUnsupportedFamilyBranches drives every family switch's default arm.
func TestUnsupportedFamilyBranches(t *testing.T) {
	b := badFamily()

	if got := b.toStringRaw(big.NewInt(1)); got != "" {
		t.Errorf("toStringRaw bad family = %q", got)
	}
	if got := b.Inspect(); got != "" {
		t.Errorf("Inspect bad family = %q", got)
	}
	if _, err := b.HtonString(); !errors.As(err, new(*AddressFamilyError)) {
		t.Errorf("HtonString bad family err = %v", err)
	}
	if got := b.Prefix(); got != 0 {
		t.Errorf("Prefix bad family = %d", got)
	}
	if _, err := b.addrMask(big.NewInt(1)); !errors.As(err, new(*AddressFamilyError)) {
		t.Errorf("addrMask bad family err = %v", err)
	}
	if err := b.maskBangLen(0); !errors.As(err, new(*AddressFamilyError)) {
		t.Errorf("maskBangLen bad family err = %v", err)
	}
	if err := b.set(big.NewInt(1)); !errors.As(err, new(*AddressFamilyError)) {
		t.Errorf("set bad family err = %v", err)
	}
	// endAddr falls back to the IPv4 mask for a non-v6 family; just exercise it.
	_ = b.endAddr()
	// predicates on a bad family all return false (their default arm).
	if b.Loopback() || b.Private() || b.LinkLocal() || b.Multicast() {
		t.Error("bad-family predicate returned true")
	}
}

// TestNotAndOpsErrorPaths covers the set()-error propagation inside the bitwise
// operators and the family-error arms of Not/Xor via a bad-family receiver.
func TestNotAndOpsErrorPaths(t *testing.T) {
	b := badFamily()
	if _, err := b.Not(); !errors.As(err, new(*AddressFamilyError)) {
		t.Errorf("Not bad family err = %v", err)
	}
	// Xor with an *IPAddr operand: coerce succeeds, then addrMask hits the
	// bad-family default arm.
	gv := &IPAddr{family: AFInet, addr: big.NewInt(1), mask: big.NewInt(1)}
	if _, err := b.Xor(gv); !errors.As(err, new(*AddressFamilyError)) {
		t.Errorf("Xor bad family err = %v", err)
	}
	// And/Or coerce other against the bad family (NewFromInt fails on Family(99)).
	if _, err := b.And(big.NewInt(1)); err == nil {
		t.Error("And bad family want err")
	}
	if _, err := b.Or(big.NewInt(1)); err == nil {
		t.Error("Or bad family want err")
	}
	// With an *IPAddr operand coerceOther succeeds (no NewFromInt), so the set()
	// error arm of And/Or/Xor is reached instead.
	good := &IPAddr{family: AFInet, addr: big.NewInt(1), mask: big.NewInt(1)}
	if _, err := b.And(good); err == nil {
		t.Error("And bad-family set want err")
	}
	if _, err := b.Or(good); err == nil {
		t.Error("Or bad-family set want err")
	}
	// Add/Sub/Succ on a bad family hit set()'s default arm.
	if _, err := b.Add(1); err == nil {
		t.Error("Add bad family want err")
	}
	if _, err := b.Sub(1); err == nil {
		t.Error("Sub bad family want err")
	}
	if _, err := b.Succ(); err == nil {
		t.Error("Succ bad family want err")
	}
}

// TestToRangeBadFamily exercises ToRange's NewFromInt error path.
func TestToRangeBadFamily(t *testing.T) {
	b := badFamily()
	if _, _, err := b.ToRange(); err == nil {
		t.Error("ToRange bad family want err")
	}
}

// TestEachBadFamily covers the NewFromInt-error return inside Each.
func TestEachBadFamily(t *testing.T) {
	// A bad family with lo<=hi so the loop body runs once and NewFromInt fails.
	b := &IPAddr{family: Family(99), addr: big.NewInt(0), mask: big.NewInt(0)}
	if err := b.Each(func(*IPAddr) error { return nil }); err == nil {
		t.Error("Each bad family want err")
	}
}

// TestIsContiguousMaskV6 covers the IPv6 arm of isContiguousMask via an IPv6
// netmask string.
func TestIsContiguousMaskV6(t *testing.T) {
	ip := mustNew(t, "2001:db8::1")
	got, err := ip.Mask("ffff:ffff::")
	if err != nil || got.Prefix() != 32 {
		t.Errorf("v6 netmask mask = %v %v", got, err)
	}
	// non-contiguous v6 mask
	if _, err := ip.Mask("ffff:0:ffff::"); !errors.As(err, new(*InvalidPrefixError)) {
		t.Errorf("v6 non-contiguous err = %v", err)
	}
}

// TestMappedCompatSetErrors covers the set()-error return inside Ipv4Mapped /
// Ipv4Compat / Native by pointing them at a bad-family receiver shaped as v4.
func TestMappedCompatSetErrors(t *testing.T) {
	// Ipv4Mapped/Compat require Ipv4(); craft a v4 whose set will still succeed,
	// so instead exercise the !ipv4 error message path which is the real branch.
	if _, err := mustNew(t, "2001:db8::1").Ipv4Mapped(); err == nil {
		t.Error("Ipv4Mapped on v6 want err")
	}
	// Native on a mapped address returns a fresh v4 (set success).
	m, _ := mustNew(t, "192.168.1.1").Ipv4Mapped()
	if n, err := m.Native(); err != nil || n.ToS() != "192.168.1.1" {
		t.Errorf("Native mapped = %v %v", n, err)
	}
}

// TestMustHexPanic covers the panic arm of mustHex.
func TestMustHexPanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("mustHex(garbage) did not panic")
		}
	}()
	_ = mustHex("zzzz")
}

// TestSplitColonsTrailing exercises the trailing-empty-field trimming and the
// fully-empty input arm of splitColons (the latter via a "::" address).
func TestSplitColonsTrailing(t *testing.T) {
	if got := splitColons(""); got != nil {
		t.Errorf("splitColons(empty) = %v", got)
	}
	if got := splitColons("a:b:"); len(got) != 2 {
		t.Errorf("splitColons trailing = %v", got)
	}
	// "::" parses with both sides empty.
	if mustNew(t, "::").ToS() != "::" {
		t.Error(":: parse")
	}
}

// TestEmptyDefaultAddress covers New("") falling through to the IPv6 default —
// MRI's IPAddr.new default is "::" but "" is an invalid address.
func TestEmptyAndDefault(t *testing.T) {
	if _, err := New(""); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("New(empty) err = %v", err)
	}
	if mustNew(t, "::").Cidr() != "::/128" {
		t.Error(":: cidr")
	}
}

// TestFamilyMismatch covers newImpl's "address family mismatch" arm: a v6-only
// string parsed under a forced IPv4 family (MRI raises AddressFamilyError).
func TestFamilyMismatch(t *testing.T) {
	if _, err := NewFamily("::1", AFInet); !errors.As(err, new(*AddressFamilyError)) {
		t.Errorf("NewFamily(::1, v4) err = %v", err)
	}
}

// TestEmbeddedV4Forms covers in6Addr's two embedded-dotted-quad arms (the full
// 6-group + v4 tail, and the compressed + v4 tail) and the bad-octet propagation.
func TestEmbeddedV4Forms(t *testing.T) {
	if got := mustNew(t, "1:2:3:4:5:6:1.2.3.4").ToS(); got != "1:2:3:4:5:6:102:304" {
		t.Errorf("full+v4 = %q", got)
	}
	if got := mustNew(t, "2001:db8::5:6:1.2.3.4").ToString(); got != "2001:0db8:0000:0000:0005:0006:0102:0304" {
		t.Errorf("compressed+v4 = %q", got)
	}
	// bad octet inside the embedded v4 of a full-form address
	if _, err := New("1:2:3:4:5:6:1.2.3.256"); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("full+bad-v4 err = %v", err)
	}
	// bad octet inside a compressed embedded v4
	if _, err := New("::1.2.3.256"); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("compressed+bad-v4 err = %v", err)
	}
	// too many groups before a compressed embedded v4
	if _, err := New("1:2:3:4:5:6:7::1.2.3.4"); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("compressed v4 overlong err = %v", err)
	}
	// too many groups on the full path (rest < 0)
	if _, err := New("1:2:3:4:5:6:7:8:9:10"); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("rest<0 err = %v", err)
	}
}

// TestV6Ops covers the IPv6 arms of addrMask (via Not/Xor) and endAddr (via
// ToRange) on a real IPv6 value.
func TestV6Ops(t *testing.T) {
	n, err := mustNew(t, "::1").Not()
	if err != nil || n.ToS() != "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe" {
		t.Errorf("~::1 = %v %v", n, err)
	}
	x, err := mustNew(t, "::1").Xor(big.NewInt(3))
	if err != nil || x.ToS() != "::2" {
		t.Errorf("::1 ^ 3 = %v %v", x, err)
	}
	lo, hi, err := mustNew(t, "2001:db8::/120").ToRange()
	if err != nil || lo.ToS() != "2001:db8::" || hi.ToS() != "2001:db8::ff" {
		t.Errorf("v6 range = %v..%v %v", lo, hi, err)
	}
}

// TestSetV6OutOfRange covers set()'s IPv6 range-check error arm via an oversize
// integer.
func TestSetV6OutOfRange(t *testing.T) {
	big6 := new(big.Int).Add(in6Mask, big.NewInt(1))
	if _, err := NewFromInt(big6, AFInet6); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("oversize v6 err = %v", err)
	}
}

// TestV6CompressedForms covers the compressed-with-embedded-v4 and the
// left/right-empty arms of in6Addr plus the to_s mapped rewrite.
func TestV6CompressedForms(t *testing.T) {
	cases := map[string]string{
		"::":              "::",
		"::1":             "::1",
		"1::":             "1::",
		"1::2":            "1::2",
		"::ffff:1.2.3.4":  "::ffff:1.2.3.4",
		"::1.2.3.4":       "::1.2.3.4",
		"1:2:3:4:5:6:7:8": "1:2:3:4:5:6:7:8",
	}
	for in, want := range cases {
		if got := mustNew(t, in).ToS(); got != want {
			t.Errorf("New(%q).ToS() = %q, want %q", in, got, want)
		}
	}
}
