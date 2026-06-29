// Copyright (c) the go-ruby-ipaddr/ipaddr authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ipaddr

import (
	"errors"
	"math/big"
	"testing"
)

// mustNew parses s or fails the test.
func mustNew(t *testing.T, s string) *IPAddr {
	t.Helper()
	ip, err := New(s)
	if err != nil {
		t.Fatalf("New(%q): %v", s, err)
	}
	return ip
}

func TestNewAndToS(t *testing.T) {
	cases := []struct{ in, toS, toStr, cidr string }{
		{"192.168.1.5/24", "192.168.1.0", "192.168.1.0", "192.168.1.0/24"},
		{"192.168.1.5", "192.168.1.5", "192.168.1.5", "192.168.1.5/32"},
		{"192.168.1.5/255.255.255.0", "192.168.1.0", "192.168.1.0", "192.168.1.0/24"},
		{"0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0/32"},
		{"1.2.3.4/0", "0.0.0.0", "0.0.0.0", "0.0.0.0/0"},
		{"::1", "::1", "0000:0000:0000:0000:0000:0000:0000:0001", "::1/128"},
		{"2001:db8::1", "2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1/128"},
		{"2001:db8::/32", "2001:db8::", "2001:0db8:0000:0000:0000:0000:0000:0000", "2001:db8::/32"},
		{"2001:db8::ab/64", "2001:db8::", "2001:0db8:0000:0000:0000:0000:0000:0000", "2001:db8::/64"},
		{"[::1]/64", "::", "0000:0000:0000:0000:0000:0000:0000:0000", "::/64"},
		{"fe80::/10", "fe80::", "fe80:0000:0000:0000:0000:0000:0000:0000", "fe80::/10"},
		{"ff02::1", "ff02::1", "ff02:0000:0000:0000:0000:0000:0000:0001", "ff02::1/128"},
		{"::ffff:1.2.3.4", "::ffff:1.2.3.4", "0000:0000:0000:0000:0000:ffff:0102:0304", "::ffff:1.2.3.4/128"},
		{"::1.2.3.4", "::1.2.3.4", "0000:0000:0000:0000:0000:0000:0102:0304", "::1.2.3.4/128"},
		{"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1/128"},
		{"1:0:0:0:0:0:0:8", "1::8", "0001:0000:0000:0000:0000:0000:0000:0008", "1::8/128"},
	}
	for _, c := range cases {
		ip := mustNew(t, c.in)
		if got := ip.ToS(); got != c.toS {
			t.Errorf("New(%q).ToS() = %q, want %q", c.in, got, c.toS)
		}
		if got := ip.ToString(); got != c.toStr {
			t.Errorf("New(%q).ToString() = %q, want %q", c.in, got, c.toStr)
		}
		if got := ip.Cidr(); got != c.cidr {
			t.Errorf("New(%q).Cidr() = %q, want %q", c.in, got, c.cidr)
		}
		if got := ip.String(); got != c.toS {
			t.Errorf("New(%q).String() = %q, want %q", c.in, got, c.toS)
		}
	}
}

func TestFamilyAndPredicateFlags(t *testing.T) {
	v4 := mustNew(t, "1.2.3.4")
	v6 := mustNew(t, "::1")
	if !v4.Ipv4() || v4.Ipv6() {
		t.Error("v4 family flags wrong")
	}
	if v6.Ipv4() || !v6.Ipv6() {
		t.Error("v6 family flags wrong")
	}
	if v4.Family() != AFInet || v6.Family() != AFInet6 {
		t.Errorf("Family = %d,%d", v4.Family(), v6.Family())
	}
}

func TestPrefix(t *testing.T) {
	if p := mustNew(t, "192.168.1.5/24").Prefix(); p != 24 {
		t.Errorf("prefix = %d", p)
	}
	if p := mustNew(t, "1.2.3.4").Prefix(); p != 32 {
		t.Errorf("host v4 prefix = %d", p)
	}
	if p := mustNew(t, "::1").Prefix(); p != 128 {
		t.Errorf("host v6 prefix = %d", p)
	}
	if p := mustNew(t, "2001:db8::/32").Prefix(); p != 32 {
		t.Errorf("v6 prefix = %d", p)
	}
}

func TestSetPrefix(t *testing.T) {
	ip := mustNew(t, "192.168.1.5")
	if _, err := ip.SetPrefix(24); err != nil {
		t.Fatal(err)
	}
	if ip.ToS() != "192.168.1.0" || ip.Prefix() != 24 {
		t.Errorf("after SetPrefix: %q/%d", ip.ToS(), ip.Prefix())
	}
	if _, err := ip.SetPrefix(99); !errors.As(err, new(*InvalidPrefixError)) {
		t.Errorf("SetPrefix(99) err = %v", err)
	}
}

func TestMask(t *testing.T) {
	got, err := mustNew(t, "192.168.1.5").Mask("24")
	if err != nil || got.ToS() != "192.168.1.0" {
		t.Errorf("Mask(24) = %v %v", got, err)
	}
	got, err = mustNew(t, "192.168.1.5").Mask("255.255.255.0")
	if err != nil || got.ToS() != "192.168.1.0" {
		t.Errorf("Mask(netmask) = %v %v", got, err)
	}
	got, err = mustNew(t, "192.168.1.5").MaskLen(16)
	if err != nil || got.ToS() != "192.168.0.0" {
		t.Errorf("MaskLen(16) = %v %v", got, err)
	}
	if _, err := mustNew(t, "1.2.3.4").MaskLen(33); !errors.As(err, new(*InvalidPrefixError)) {
		t.Errorf("MaskLen(33) err = %v", err)
	}
	// non-contiguous netmask
	if _, err := mustNew(t, "1.2.3.4").Mask("255.0.255.0"); !errors.As(err, new(*InvalidPrefixError)) {
		t.Errorf("non-contiguous mask err = %v", err)
	}
	// netmask of different family
	if _, err := mustNew(t, "::1").Mask("255.255.255.0"); !errors.As(err, new(*InvalidPrefixError)) {
		t.Errorf("cross-family mask err = %v", err)
	}
	// invalid netmask string passed to Mask
	if _, err := mustNew(t, "1.2.3.4").Mask("not.an.ip.x"); err == nil {
		t.Error("Mask(garbage) want err")
	}
}

func TestInclude(t *testing.T) {
	net := mustNew(t, "10.0.0.0/8")
	for _, in := range []any{"10.1.2.3", mustNew(t, "10.255.255.255"), big.NewInt(0x0a010203), 0x0a010203, int64(0x0a010203), uint64(0x0a010203)} {
		ok, err := net.Include(in)
		if err != nil || !ok {
			t.Errorf("Include(%v) = %v %v", in, ok, err)
		}
	}
	ok, _ := net.Include("11.0.0.1")
	if ok {
		t.Error("Include outside = true")
	}
	// different family
	ok, err := net.Include(mustNew(t, "::1"))
	if err != nil || ok {
		t.Errorf("cross-family Include = %v %v", ok, err)
	}
	// subnet
	ok, _ = mustNew(t, "192.168.1.0/24").Include(mustNew(t, "192.168.1.128/25"))
	if !ok {
		t.Error("subnet Include = false")
	}
	// uncoercible
	if _, err := net.Include(3.14); err == nil {
		t.Error("Include(float) want err")
	}
}

func TestBitwiseOps(t *testing.T) {
	a := mustNew(t, "192.168.1.5/24")
	if n, err := a.Not(); err != nil || n.ToS() != "63.87.254.255" {
		t.Errorf("~ = %v %v", n, err)
	}
	if o, err := a.Or(0x05); err != nil || o.ToS() != "192.168.1.5" || o.Prefix() != 24 {
		t.Errorf("| = %v %v", o, err)
	}
	if n, err := a.And(0xffff0000); err != nil || n.ToS() != "192.168.0.0" {
		t.Errorf("& = %v %v", n, err)
	}
	// a is masked to 192.168.1.0, so XOR 0x0f -> 192.168.1.15.
	if x, err := a.Xor(0x0000000f); err != nil || x.ToS() != "192.168.1.15" {
		t.Errorf("^ = %v %v", x, err)
	}
	or := mustNew(t, "10.0.0.0/8")
	if v, err := or.Or(0x00010203); err != nil || v.ToS() != "10.1.2.3" {
		t.Errorf("| oracle = %v %v", v, err)
	}
	// add/sub
	if v, err := mustNew(t, "1.2.3.4").Add(1); err != nil || v.ToS() != "1.2.3.5" {
		t.Errorf("Add = %v %v", v, err)
	}
	if v, err := mustNew(t, "1.2.3.4").Sub(1); err != nil || v.ToS() != "1.2.3.3" {
		t.Errorf("Sub = %v %v", v, err)
	}
	// error propagation on bad operand
	for _, fn := range []func() error{
		func() error { _, e := a.And(3.14); return e },
		func() error { _, e := a.Or(3.14); return e },
		func() error { _, e := a.Xor(3.14); return e },
	} {
		if fn() == nil {
			t.Error("bad-operand op want err")
		}
	}
}

func TestSucc(t *testing.T) {
	if s, err := mustNew(t, "192.168.1.2").Succ(); err != nil || s.ToS() != "192.168.1.3" {
		t.Errorf("succ = %v %v", s, err)
	}
	if s, err := mustNew(t, "::1").Succ(); err != nil || s.ToS() != "::2" {
		t.Errorf("succ v6 = %v %v", s, err)
	}
	// overflow at broadcast
	if _, err := mustNew(t, "255.255.255.255").Succ(); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("succ overflow err = %v", err)
	}
}

func TestCmpEqlHash(t *testing.T) {
	if c, ok := mustNew(t, "1.2.3.4").Cmp(mustNew(t, "1.2.3.5")); !ok || c != -1 {
		t.Errorf("cmp = %d %v", c, ok)
	}
	if c, ok := mustNew(t, "1.2.3.5").Cmp("1.2.3.4"); !ok || c != 1 {
		t.Errorf("cmp = %d %v", c, ok)
	}
	if c, ok := mustNew(t, "1.2.3.4").Cmp("1.2.3.4"); !ok || c != 0 {
		t.Errorf("cmp eq = %d %v", c, ok)
	}
	if _, ok := mustNew(t, "1.2.3.4").Cmp(mustNew(t, "::1")); ok {
		t.Error("cross-family cmp ok")
	}
	if _, ok := mustNew(t, "1.2.3.4").Cmp(3.14); ok {
		t.Error("uncoercible cmp ok")
	}
	if !mustNew(t, "1.2.3.4").Eql(mustNew(t, "1.2.3.4")) {
		t.Error("eql false")
	}
	if !mustNew(t, "1.2.3.4").Eql(0x01020304) {
		t.Error("eql int false")
	}
	if mustNew(t, "1.2.3.4").Eql(mustNew(t, "::1")) {
		t.Error("cross-family eql true")
	}
	if mustNew(t, "1.2.3.4").Eql(3.14) {
		t.Error("uncoercible eql true")
	}
	h1 := mustNew(t, "1.2.3.4").Hash()
	h2 := mustNew(t, "1.2.3.4").Hash()
	if h1 != h2 {
		t.Error("hash not stable")
	}
	if mustNew(t, "1.2.3.4").Hash() == mustNew(t, "1.2.3.5").Hash() {
		t.Error("hash collision on distinct addrs")
	}
	if h1&1 != 0 || mustNew(t, "::1").Hash()&1 != 1 {
		t.Error("hash parity bit wrong")
	}
}

func TestToRangeAndEach(t *testing.T) {
	lo, hi, err := mustNew(t, "192.168.1.5/24").ToRange()
	if err != nil || lo.ToS() != "192.168.1.0" || hi.ToS() != "192.168.1.255" {
		t.Errorf("range = %v..%v %v", lo, hi, err)
	}
	if lo.Prefix() != 32 || hi.Prefix() != 32 {
		t.Errorf("range endpoint prefixes = %d,%d", lo.Prefix(), hi.Prefix())
	}
	var got []string
	if err := mustNew(t, "192.168.1.0/30").Each(func(a *IPAddr) error {
		got = append(got, a.ToS())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}
	if len(got) != len(want) {
		t.Fatalf("each count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("each[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// early stop
	stop := errors.New("stop")
	n := 0
	if err := mustNew(t, "10.0.0.0/8").Each(func(*IPAddr) error { n++; return stop }); err != stop {
		t.Errorf("each early-stop err = %v", err)
	}
	if n != 1 {
		t.Errorf("each early-stop visited %d", n)
	}
}

func TestPredicates(t *testing.T) {
	cases := []struct {
		in        string
		loopback  bool
		private   bool
		linkLocal bool
		multicast bool
	}{
		{"127.0.0.1", true, false, false, false},
		{"10.0.0.1", false, true, false, false},
		{"172.16.0.1", false, true, false, false},
		{"192.168.1.1", false, true, false, false},
		{"169.254.1.1", false, false, true, false},
		{"224.0.0.1", false, false, false, true},
		{"8.8.8.8", false, false, false, false},
		{"::1", true, false, false, false},
		{"fc00::1", false, true, false, false},
		{"fe80::1", false, false, true, false},
		{"ff02::1", false, false, false, true},
		{"2001:db8::1", false, false, false, false},
		{"::ffff:127.0.0.1", true, false, false, false},
		{"::ffff:10.0.0.1", false, true, false, false},
		{"::ffff:172.16.0.1", false, true, false, false},
		{"::ffff:192.168.0.1", false, true, false, false},
		{"::ffff:169.254.0.1", false, false, true, false},
	}
	for _, c := range cases {
		ip := mustNew(t, c.in)
		if ip.Loopback() != c.loopback {
			t.Errorf("%s loopback = %v", c.in, ip.Loopback())
		}
		if ip.Private() != c.private {
			t.Errorf("%s private = %v", c.in, ip.Private())
		}
		if ip.LinkLocal() != c.linkLocal {
			t.Errorf("%s link_local = %v", c.in, ip.LinkLocal())
		}
		if ip.Multicast() != c.multicast {
			t.Errorf("%s multicast = %v", c.in, ip.Multicast())
		}
	}
}

func TestMappedCompatNative(t *testing.T) {
	m, err := mustNew(t, "192.168.1.1").Ipv4Mapped()
	if err != nil || m.ToS() != "::ffff:192.168.1.1" {
		t.Errorf("ipv4_mapped = %v %v", m, err)
	}
	if !m.IsIpv4Mapped() {
		t.Error("IsIpv4Mapped false")
	}
	c, err := mustNew(t, "192.168.1.1").Ipv4Compat()
	if err != nil || c.ToS() != "::192.168.1.1" {
		t.Errorf("ipv4_compat = %v %v", c, err)
	}
	if !c.IsIpv4Compat() {
		t.Error("IsIpv4Compat false")
	}
	// native of mapped/compat
	if n, err := m.Native(); err != nil || n.ToS() != "192.168.1.1" {
		t.Errorf("native of mapped = %v %v", n, err)
	}
	if n, err := c.Native(); err != nil || n.ToS() != "192.168.1.1" {
		t.Errorf("native of compat = %v %v", n, err)
	}
	// native of plain v4 returns self
	v4 := mustNew(t, "1.2.3.4")
	if n, _ := v4.Native(); n != v4 {
		t.Error("native of v4 not self")
	}
	// native of plain v6 returns self
	v6 := mustNew(t, "2001:db8::1")
	if n, _ := v6.Native(); n != v6 {
		t.Error("native of v6 not self")
	}
	// mapping a v6 errors
	if _, err := mustNew(t, "::1").Ipv4Mapped(); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("ipv4_mapped of v6 err = %v", err)
	}
	if _, err := mustNew(t, "::1").Ipv4Compat(); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("ipv4_compat of v6 err = %v", err)
	}
	// flags on plain addrs
	if mustNew(t, "::1").IsIpv4Mapped() || mustNew(t, "::1").IsIpv4Compat() {
		t.Error("::1 mapped/compat flags true")
	}
	if mustNew(t, "1.2.3.4").IsIpv4Mapped() {
		t.Error("v4 mapped flag true")
	}
}

func TestHtonAndNtop(t *testing.T) {
	b, err := mustNew(t, "1.2.3.4").HtonString()
	if err != nil || len(b) != 4 || b[0] != 1 || b[3] != 4 {
		t.Errorf("hton v4 = %v %v", b, err)
	}
	b, err = mustNew(t, "::1").HtonString()
	if err != nil || len(b) != 16 || b[15] != 1 {
		t.Errorf("hton v6 = %v %v", b, err)
	}
	if s, err := Ntop([]byte{1, 2, 3, 4}); err != nil || s != "1.2.3.4" {
		t.Errorf("ntop v4 = %q %v", s, err)
	}
	v6 := make([]byte, 16)
	v6[15] = 1
	if s, err := Ntop(v6); err != nil || s != "0000:0000:0000:0000:0000:0000:0000:0001" {
		t.Errorf("ntop v6 = %q %v", s, err)
	}
	if _, err := Ntop([]byte{1, 2, 3}); !errors.As(err, new(*AddressFamilyError)) {
		t.Errorf("ntop bad len err = %v", err)
	}
	ip, err := NewNtoh([]byte{1, 2, 3, 4})
	if err != nil || ip.ToS() != "1.2.3.4" {
		t.Errorf("new_ntoh = %v %v", ip, err)
	}
	if _, err := NewNtoh([]byte{1}); err == nil {
		t.Error("new_ntoh bad len want err")
	}
}

func TestNewFromIntAndFamily(t *testing.T) {
	ip, err := NewFromInt(big.NewInt(0x01020304), AFInet)
	if err != nil || ip.ToS() != "1.2.3.4" {
		t.Errorf("from int = %v %v", ip, err)
	}
	if _, err := NewFromInt(big.NewInt(1), afUnspec); !errors.As(err, new(*AddressFamilyError)) {
		t.Errorf("from int unspec err = %v", err)
	}
	if _, err := NewFromInt(big.NewInt(1), Family(99)); !errors.As(err, new(*AddressFamilyError)) {
		t.Errorf("from int bad family err = %v", err)
	}
	// out-of-range integer
	big5 := new(big.Int).Add(in4Mask, big.NewInt(1))
	if _, err := NewFromInt(big5, AFInet); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("from int oversize err = %v", err)
	}
	// NewFamily forcing
	if ip, err := NewFamily("1.2.3.4", AFInet); err != nil || ip.ToS() != "1.2.3.4" {
		t.Errorf("NewFamily v4 = %v %v", ip, err)
	}
	// MRI forces the v6 path, which fails to parse "1.2.3.4" as IPv6 and raises
	// InvalidAddressError (not AddressFamilyError) before the family check.
	if _, err := NewFamily("1.2.3.4", AFInet6); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("NewFamily mismatch err = %v", err)
	}
	if ip, err := NewFamily("::1", AFInet6); err != nil || ip.ToS() != "::1" {
		t.Errorf("NewFamily v6 = %v %v", ip, err)
	}
}

func TestInspectAndNetmask(t *testing.T) {
	if s := mustNew(t, "192.168.1.5/24").Inspect(); s != "#<IPAddr: IPv4:192.168.1.0/255.255.255.0>" {
		t.Errorf("inspect v4 = %q", s)
	}
	want6 := "#<IPAddr: IPv6:2001:0db8:0000:0000:0000:0000:0000:0000/ffff:ffff:ffff:ffff:0000:0000:0000:0000>"
	if s := mustNew(t, "2001:db8::1/64").Inspect(); s != want6 {
		t.Errorf("inspect v6 = %q", s)
	}
	if s := mustNew(t, "1.2.3.4").Inspect(); s != "#<IPAddr: IPv4:1.2.3.4/255.255.255.255>" {
		t.Errorf("inspect host = %q", s)
	}
	if s := mustNew(t, "192.168.1.0/24").Netmask(); s != "255.255.255.0" {
		t.Errorf("netmask = %q", s)
	}
}

func TestZoneID(t *testing.T) {
	ip := mustNew(t, "fe80::1%eth0")
	if ip.ToS() != "fe80::1%eth0" {
		t.Errorf("zone to_s = %q", ip.ToS())
	}
	if ip.ToString() != "fe80:0000:0000:0000:0000:0000:0000:0001%eth0" {
		t.Errorf("zone to_string = %q", ip.ToString())
	}
}

func TestParseErrors(t *testing.T) {
	type want struct {
		msg string
		// kind: 0 invalid-address, 1 invalid-prefix, 2 family
		kind int
	}
	cases := map[string]want{
		"999.1.1.1":     {"invalid address: 999.1.1.1", 0},
		"1.2.3":         {"invalid address: ", 0},
		"1.2.3.4.5":     {"invalid address: ", 0},
		"hello":         {"invalid address: ", 0},
		"::g":           {"invalid address: ", 0},
		"1.2.3.4/abc":   {"invalid address: ", 0},
		"1.2.3.4/33":    {"invalid length", 1},
		"1.2.3.4/-1":    {"invalid address: ", 0},
		"::1/129":       {"invalid length", 1},
		"192.168.001.1": {"zero-filled number in IPv4 address is ambiguous: 192.168.001.1", 0},
		"1.2.3.4/01":    {"leading zeros in prefix", 1},
	}
	for in, w := range cases {
		_, err := New(in)
		if err == nil {
			t.Errorf("New(%q) expected error", in)
			continue
		}
		if err.Error() != w.msg {
			t.Errorf("New(%q) msg = %q, want %q", in, err.Error(), w.msg)
		}
		switch w.kind {
		case 0:
			if !errors.As(err, new(*InvalidAddressError)) {
				t.Errorf("New(%q) kind != InvalidAddressError: %T", in, err)
			}
		case 1:
			if !errors.As(err, new(*InvalidPrefixError)) {
				t.Errorf("New(%q) kind != InvalidPrefixError: %T", in, err)
			}
		}
	}
	// over-long v6 (too many groups)
	if _, err := New("1:2:3:4:5:6:7:8:9"); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("overlong v6 err = %v", err)
	}
	// compressed with too many groups around ::
	if _, err := New("1:2:3:4:5:6:7:8::9"); !errors.As(err, new(*InvalidAddressError)) {
		t.Errorf("compressed overlong err = %v", err)
	}
}

func TestErrorTypes(t *testing.T) {
	// Ensure each error type renders its message.
	for _, e := range []error{
		&Error{"base"},
		&InvalidAddressError{"addr"},
		&InvalidPrefixError{"pfx"},
		&AddressFamilyError{"fam"},
	} {
		if e.Error() == "" {
			t.Errorf("%T empty message", e)
		}
	}
}

func TestToI(t *testing.T) {
	if mustNew(t, "1.2.3.4").ToI().Cmp(big.NewInt(0x01020304)) != 0 {
		t.Error("to_i v4 wrong")
	}
	if mustNew(t, "::1").ToI().Cmp(big.NewInt(1)) != 0 {
		t.Error("to_i v6 wrong")
	}
}
