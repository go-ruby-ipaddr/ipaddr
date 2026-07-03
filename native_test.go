// Copyright (c) the go-ruby-ipaddr/ipaddr authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ipaddr

import (
	"errors"
	"math"
	"math/big"
	"math/rand"
	"testing"
)

// TestZoneSplit drives every arm of the %zone detector directly (no leading '%',
// '%' at end, a non-word tail, and a valid zone).
func TestZoneSplit(t *testing.T) {
	cases := map[string]int{
		"fe80::1":      -1, // no '%'
		"fe80::1%":     -1, // '%' is the last byte
		"fe80::1%e.f":  -1, // trailing '.' is not a word char
		"fe80::1%eth0": len("fe80::1"),
	}
	for in, want := range cases {
		if got := zoneSplit(in); got != want {
			t.Errorf("zoneSplit(%q) = %d, want %d", in, got, want)
		}
	}
	// A '%' that is not a valid zone leaves the address unparseable.
	if _, err := New("fe80::1%"); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("New(zone-less %%) err = %v", err)
	}
}

// TestIn6FastDefers exercises inputs the fast IPv6 parser declines, each of which
// the regexp fallback then rejects with MRI's message.
func TestIn6FastDefers(t *testing.T) {
	bad := []string{
		"1::2::3",          // two "::"
		":::",              // triple colon
		"1:::2",            // "::" abutting a third colon
		"1:2:3:4::5:6:7:8", // eight groups leave no room for "::"
		"12345::1",         // over-long hextet
		"1:2:3",            // fewer than eight groups, no "::"
		"::12345",          // over-long hextet after "::"
		"1:2:3:4:5:6:7",    // seven groups, no "::"
		"g::1",             // non-hex hextet
	}
	for _, in := range bad {
		if _, err := New(in); !errors.As(err, new(*InvalidAddressError)) {
			t.Errorf("New(%q) err = %v, want InvalidAddressError", in, err)
		}
	}
	// Uppercase hex must parse (case-insensitive) and lowercase in to_s.
	if got := mustNew(t, "ABCD::EF").ToS(); got != "abcd::ef" {
		t.Errorf("uppercase parse = %q", got)
	}
	// A lone zero group (no run >= 2) stays "0" — exercises appendHex's zero arm.
	if got := mustNew(t, "1:0:2:0:3:0:4:0").ToS(); got != "1:0:2:0:3:0:4:0" {
		t.Errorf("lone-zero to_s = %q", got)
	}
}

// TestZoneMappedFormatting locks down the zone/embedded-IPv4 to_s interaction
// with values verified byte-for-byte against MRI 4.0.5: a %zone suffix suppresses
// the dotted-quad rewrite (MRI's anchored regex no longer matches), while the
// compat/mapped rewrite fires only when there is no zone.
func TestZoneMappedFormatting(t *testing.T) {
	want := map[string][2]string{
		"::ffff:1.2.3.4%eth0": {"::ffff:102:304%eth0", "0000:0000:0000:0000:0000:ffff:0102:0304%eth0"},
		"::1.2.3.4%eth0":      {"::102:304%eth0", "0000:0000:0000:0000:0000:0000:0102:0304%eth0"},
		"::ffff:0:0":          {"::ffff:0.0.0.0", "0000:0000:0000:0000:0000:ffff:0000:0000"},
		"::0.0.0.2":           {"::2", "0000:0000:0000:0000:0000:0000:0000:0002"},
		"0:0:0:0:0:0:2:3":     {"::0.2.0.3", "0000:0000:0000:0000:0000:0000:0002:0003"},
		"1:0:0:1:0:0:0:1":     {"1:0:0:1::1", "0001:0000:0000:0001:0000:0000:0000:0001"},
		"::255.255.255.255":   {"::255.255.255.255", "0000:0000:0000:0000:0000:0000:ffff:ffff"},
		"ffff::ffff:1.2.3.4":  {"ffff::ffff:102:304", "ffff:0000:0000:0000:0000:ffff:0102:0304"},
		// All-zeros with a zone: the anchored "::" collapse cannot fire, so MRI
		// leaves a trailing "0".
		"::%eth0": {"::0%eth0", "0000:0000:0000:0000:0000:0000:0000:0000%eth0"},
	}
	for in, w := range want {
		ip := mustNew(t, in)
		if ip.ToS() != w[0] || ip.ToString() != w[1] {
			t.Errorf("%q: to_s=%q(want %q) to_string=%q(want %q)", in, ip.ToS(), w[0], ip.ToString(), w[1])
		}
	}
}

// TestClassifyPrefixEdges covers the empty and integer-overflow prefix arms.
func TestClassifyPrefixEdges(t *testing.T) {
	// Empty mask ("addr/") falls to the netmask-string branch, which fails to
	// parse the empty netmask.
	if _, err := New("1.2.3.4/"); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("New(1.2.3.4/) err = %v", err)
	}
	// A prefix length that overflows int is treated as huge and fails the range
	// check with "invalid length".
	if _, err := New("1.2.3.4/999999999999999999999999"); !errors.As(err, new(*InvalidPrefixError)) {
		t.Errorf("New(overflow prefix) err = %v", err)
	}
}

// TestShiftBranches drives lsh/rsh across their n==0, n<64, 64<=n<128 and n>=128
// arms via prefix masking at representative lengths.
func TestShiftBranches(t *testing.T) {
	cases := []struct{ in, cidr string }{
		{"2001:db8::1/128", "2001:db8::1/128"}, // masklen 0  -> n==0
		{"2001:db8::/120", "2001:db8::/120"},   // masklen 8  -> n<64
		{"2001:db8::/64", "2001:db8::/64"},     // masklen 64 -> n>=64
		{"2001:db8::/32", "2001:db8::/32"},     // masklen 96 -> n>=64
		{"2001:db8::/0", "::/0"},               // masklen128 -> n>=128
	}
	for _, c := range cases {
		if got := mustNew(t, c.in).Cidr(); got != c.cidr {
			t.Errorf("New(%q).Cidr() = %q, want %q", c.in, got, c.cidr)
		}
	}
}

// TestArithmeticOverflow covers the big.Int fallback of #+/#-/#succ at the edges
// of the address space, including the math.MinInt64 offset and the carry/borrow
// across the 64-bit word boundary.
func TestArithmeticOverflow(t *testing.T) {
	// IPv6 broadcast succ overflows 2^128 -> out-of-range InvalidAddressError.
	maxV6 := mustNew(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	if _, err := maxV6.Succ(); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("v6 succ overflow err = %v", err)
	}
	// Subtracting below zero underflows -> negative value rejected.
	if _, err := mustNew(t, "::").Sub(1); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("v6 sub underflow err = %v", err)
	}
	// The math.MinInt64 magnitude branch of addOffset.
	if _, err := mustNew(t, "::").Add(math.MinInt64); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("Add(MinInt64) err = %v", err)
	}
	// Carry across the low word: succ of ::ffff:ffff:ffff:ffff sets bit 64.
	s, err := mustNew(t, "::ffff:ffff:ffff:ffff").Succ()
	if err != nil || s.ToString() != "0000:0000:0000:0001:0000:0000:0000:0000" {
		t.Errorf("carry succ = %v %v", s, err)
	}
	// Borrow across the low word.
	d, err := mustNew(t, "0:0:0:1:0:0:0:0").Sub(1)
	if err != nil || d.ToString() != "0000:0000:0000:0000:ffff:ffff:ffff:ffff" {
		t.Errorf("borrow sub = %v %v", d, err)
	}
}

// TestEachAtTop covers Each's addOffset-overflow break: a /128 at the top of the
// IPv6 space is visited once, then the successor overflows and iteration stops.
func TestEachAtTop(t *testing.T) {
	n := 0
	err := mustNew(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").Each(func(*IPAddr) error {
		n++
		return nil
	})
	if err != nil || n != 1 {
		t.Errorf("Each at top: n=%d err=%v", n, err)
	}
}

// TestIsContiguousMaskBadFamily covers the unsupported-family arm directly.
func TestIsContiguousMaskBadFamily(t *testing.T) {
	if isContiguousMask(u128{0, 1}, Family(99)) {
		t.Error("isContiguousMask bad family = true")
	}
}

// TestU128BigRoundTrip checks the big.Int bridge in both directions, including
// the low/high word split, and the out-of-range report.
func TestU128BigRoundTrip(t *testing.T) {
	for _, v := range []u128{{0, 0}, {0, 1}, {0, math.MaxUint64}, {1, 0}, {math.MaxUint64, math.MaxUint64}} {
		b := v.big()
		got, ok := bigToU128(b)
		if !ok || got != v {
			t.Errorf("round-trip %v -> %s -> %v (ok=%v)", v, b.String(), got, ok)
		}
	}
	if _, ok := bigToU128(big.NewInt(-1)); ok {
		t.Error("bigToU128(-1) ok")
	}
	if _, ok := bigToU128(new(big.Int).Lsh(big.NewInt(1), 128)); ok {
		t.Error("bigToU128(2^128) ok")
	}
}

// randV6Expanded returns a random fully-expanded IPv6 string, biased toward zero
// groups (to exercise the compressor's runs) and toward the v4-mapped / v4-compat
// prefixes (to exercise the embedded-quad rewrite).
func randV6Expanded(r *rand.Rand) string {
	var h [8]uint16
	for j := range h {
		if r.Intn(3) == 0 {
			h[j] = 0
		} else {
			h[j] = uint16(r.Intn(0x10000))
		}
	}
	switch r.Intn(6) {
	case 0:
		h = [8]uint16{0, 0, 0, 0, 0, 0xffff, h[6], h[7]}
	case 1:
		h = [8]uint16{0, 0, 0, 0, 0, 0, h[6], h[7]}
	}
	var b []byte
	for j := 0; j < 8; j++ {
		if j > 0 {
			b = append(b, ':')
		}
		b = appendHex4(b, h[j])
	}
	// Occasionally attach a %zone so the zone/embedded-IPv4 suppression path is
	// fuzzed against MRI too.
	if r.Intn(4) == 0 {
		b = append(b, "%eth0"...)
	}
	return string(b)
}

// TestOracleRandomV6 fuzzes both directions against MRI over a large random
// corpus: the regexp-free to_s compressor (byte-identical output on the expanded
// form) and the hand-rolled fast parser (re-parsing the compact to_s and checking
// the fully-expanded to_string round-trips). Skips without MRI 4.0+.
func TestOracleRandomV6(t *testing.T) {
	bin := rubyBin(t)
	r := rand.New(rand.NewSource(20260703))
	for i := 0; i < 500; i++ {
		in := randV6Expanded(r)
		ip := mustNew(t, in)
		compact := ip.ToS()

		// (1) to_s / to_string on the expanded form must match MRI exactly.
		got := compact + "\x1f" + ip.ToString()
		script := "a = IPAddr.new(" + rbStr(in) + ")\nprint [a.to_s, a.to_string].join(\"\\x1f\")\n"
		if want := rubyEval(t, bin, script); got != want {
			t.Fatalf("to_s mismatch for %q:\n  go   = %q\n  ruby = %q", in, got, want)
		}

		// (2) re-parsing the compact form (which the fast parser handles) must
		// yield the same expanded value MRI produces.
		reparsed := mustNew(t, compact).ToString()
		script2 := "print IPAddr.new(" + rbStr(compact) + ").to_string\n"
		if want := rubyEval(t, bin, script2); reparsed != want {
			t.Fatalf("reparse mismatch for %q:\n  go   = %q\n  ruby = %q", compact, reparsed, want)
		}
	}
}
