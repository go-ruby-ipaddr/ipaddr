// Copyright (c) the go-ruby-ipaddr/ipaddr authors
//
// SPDX-License-Identifier: BSD-3-Clause

package ipaddr

import (
	"math/big"
	"os/exec"
	"strings"
	"testing"
)

// rubyBin locates a usable `ruby` whose IPAddr semantics this package targets
// (MRI 4.0+). The oracle tests skip themselves when ruby is absent (the Windows
// lane and the qemu cross-arch lanes) or older than 4.0, so the deterministic
// ruby-free suite alone keeps coverage at 100% there.
func rubyBin(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ruby")
	if err != nil {
		t.Skip("ruby not on PATH; skipping MRI oracle")
	}
	// Gate on RUBY_VERSION >= "4.0".
	out, err := exec.Command(path, "-e", "print RUBY_VERSION").Output()
	if err != nil {
		t.Skipf("cannot read RUBY_VERSION: %v", err)
	}
	if string(out) < "4.0" {
		t.Skipf("ruby %s < 4.0; skipping MRI oracle", out)
	}
	return path
}

// rubyEval runs a Ruby script under `ruby -ripaddr` and returns trimmed stdout.
// The script $stdout.binmode/$stdin.binmode itself so Windows text-mode never
// pollutes the bytes (the go-ruby-erb lesson); the shared preamble does so.
func rubyEval(t *testing.T, bin, script string) string {
	t.Helper()
	pre := "$stdout.binmode\n$stdin.binmode\n"
	cmd := exec.Command(bin, "-ripaddr", "-e", pre+script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ruby error: %v\nscript:\n%s\noutput:\n%s", err, script, out)
	}
	return strings.TrimRight(string(out), "\n")
}

// TestOracleToS checks ToS / ToString / Cidr / Inspect / Netmask against MRI for
// a corpus spanning IPv4, IPv6, masked, compressed and embedded-v4 forms.
func TestOracleToS(t *testing.T) {
	bin := rubyBin(t)
	corpus := []string{
		"192.168.1.5/24", "192.168.1.5", "192.168.1.5/255.255.255.0",
		"10.0.0.0/8", "0.0.0.0", "1.2.3.4/0", "255.255.255.255",
		"::1", "2001:db8::1", "2001:db8::/32", "2001:db8::ab/64",
		"[::1]/64", "fe80::/10", "ff02::1", "::ffff:1.2.3.4", "::1.2.3.4",
		"2001:0db8:0000:0000:0000:0000:0000:0001", "1:0:0:0:0:0:0:8",
		"1:2:3:4:5:6:1.2.3.4", "2001:db8::5:6:1.2.3.4", "fe80::1%eth0",
	}
	for _, in := range corpus {
		ip := mustNew(t, in)
		got := strings.Join([]string{ip.ToS(), ip.ToString(), ip.Cidr(), ip.Inspect(), ip.Netmask()}, "\x1f")
		script := "a = IPAddr.new(" + rbStr(in) + ")\n" +
			"print [a.to_s, a.to_string, a.cidr, a.inspect, a.netmask].join(\"\\x1f\")\n"
		want := rubyEval(t, bin, script)
		if got != want {
			t.Errorf("IPAddr.new(%q):\n  go   = %q\n  ruby = %q", in, got, want)
		}
	}
}

// TestOraclePredicates checks ipv4?/ipv6?/prefix/loopback?/private?/link_local?
// against MRI (MRI 4.0.5 has no multicast?, so it is excluded here).
func TestOraclePredicates(t *testing.T) {
	bin := rubyBin(t)
	corpus := []string{
		"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1",
		"8.8.8.8", "224.0.0.1", "::1", "fc00::1", "fe80::1", "2001:db8::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.0.1",
		"192.168.1.5/24", "2001:db8::/48",
	}
	for _, in := range corpus {
		ip := mustNew(t, in)
		got := strings.Join([]string{
			b2s(ip.Ipv4()), b2s(ip.Ipv6()), itoa(ip.Prefix()),
			b2s(ip.Loopback()), b2s(ip.Private()), b2s(ip.LinkLocal()),
		}, ",")
		script := "a = IPAddr.new(" + rbStr(in) + ")\n" +
			"print [a.ipv4?, a.ipv6?, a.prefix, a.loopback?, a.private?, a.link_local?].join(\",\")\n"
		want := rubyEval(t, bin, script)
		if got != want {
			t.Errorf("predicates(%q):\n  go   = %q\n  ruby = %q", in, got, want)
		}
	}
}

// TestOracleOps checks the bitwise/compare operators, succ, include? and
// to_range endpoints against MRI.
func TestOracleOps(t *testing.T) {
	bin := rubyBin(t)

	// |, &, ~ on a masked network.
	a := mustNew(t, "10.0.0.0/8")
	or, _ := a.Or(big.NewInt(0x00010203))
	if want := rubyEval(t, bin, `print (IPAddr.new("10.0.0.0/8") | 0x00010203).to_s`); or.ToS() != want {
		t.Errorf("| = %q, ruby %q", or.ToS(), want)
	}
	and, _ := mustNew(t, "192.168.1.5").And(big.NewInt(0xffffff00))
	if want := rubyEval(t, bin, `print (IPAddr.new("192.168.1.5") & 0xffffff00).to_s`); and.ToS() != want {
		t.Errorf("& = %q, ruby %q", and.ToS(), want)
	}
	not, _ := mustNew(t, "0.0.0.0").Not()
	if want := rubyEval(t, bin, `print (~IPAddr.new("0.0.0.0")).to_s`); not.ToS() != want {
		t.Errorf("~ = %q, ruby %q", not.ToS(), want)
	}

	// succ on v4 and v6.
	for _, in := range []string{"192.168.1.2", "::1"} {
		s, _ := mustNew(t, in).Succ()
		want := rubyEval(t, bin, "print IPAddr.new("+rbStr(in)+").succ.to_s")
		if s.ToS() != want {
			t.Errorf("succ(%q) = %q, ruby %q", in, s.ToS(), want)
		}
	}

	// <=> and include?.
	c, _ := mustNew(t, "1.2.3.4").Cmp(mustNew(t, "1.2.3.5"))
	if want := rubyEval(t, bin, `print(IPAddr.new("1.2.3.4") <=> IPAddr.new("1.2.3.5"))`); itoa(c) != want {
		t.Errorf("<=> = %d, ruby %q", c, want)
	}
	inc, _ := mustNew(t, "192.168.1.0/24").Include("192.168.1.99")
	if want := rubyEval(t, bin, `print IPAddr.new("192.168.1.0/24").include?("192.168.1.99")`); b2s(inc) != want {
		t.Errorf("include? = %v, ruby %q", inc, want)
	}

	// to_range endpoints.
	lo, hi, _ := mustNew(t, "192.168.1.5/24").ToRange()
	want := rubyEval(t, bin, `r = IPAddr.new("192.168.1.5/24").to_range; print [r.begin.to_s, r.end.to_s].join(",")`)
	if got := lo.ToS() + "," + hi.ToS(); got != want {
		t.Errorf("to_range = %q, ruby %q", got, want)
	}
}

// TestOracleMappedNativeHton checks ipv4_mapped / ipv4_compat / native / hton
// against MRI.
func TestOracleMappedNativeHton(t *testing.T) {
	bin := rubyBin(t)
	m, _ := mustNew(t, "192.168.1.1").Ipv4Mapped()
	if want := rubyEval(t, bin, `print IPAddr.new("192.168.1.1").ipv4_mapped.to_s`); m.ToS() != want {
		t.Errorf("ipv4_mapped = %q, ruby %q", m.ToS(), want)
	}
	c, _ := mustNew(t, "192.168.1.1").Ipv4Compat()
	if want := rubyEval(t, bin, `print IPAddr.new("192.168.1.1").ipv4_compat.to_s`); c.ToS() != want {
		t.Errorf("ipv4_compat = %q, ruby %q", c.ToS(), want)
	}
	n, _ := m.Native()
	if want := rubyEval(t, bin, `print IPAddr.new("192.168.1.1").ipv4_mapped.native.to_s`); n.ToS() != want {
		t.Errorf("native = %q, ruby %q", n.ToS(), want)
	}
	hb, _ := mustNew(t, "1.2.3.4").HtonString()
	want := rubyEval(t, bin, `print IPAddr.new("1.2.3.4").hton.bytes.join(",")`)
	got := make([]string, len(hb))
	for i, v := range hb {
		got[i] = itoa(int(v))
	}
	if strings.Join(got, ",") != want {
		t.Errorf("hton = %v, ruby %q", got, want)
	}
}

// TestOracleErrors checks the error class and message for invalid inputs against
// MRI, exercising the InvalidAddressError / InvalidPrefixError messages.
func TestOracleErrors(t *testing.T) {
	bin := rubyBin(t)
	corpus := []string{
		"999.1.1.1", "1.2.3", "hello", "::g",
		"1.2.3.4/33", "::1/129", "192.168.001.1", "1.2.3.4/01",
	}
	for _, in := range corpus {
		_, err := New(in)
		if err == nil {
			t.Errorf("New(%q) expected error", in)
			continue
		}
		got := errClass(err) + ": " + err.Error()
		script := "begin; IPAddr.new(" + rbStr(in) + "); rescue => e; print \"#{e.class}: #{e.message}\"; end"
		want := rubyEval(t, bin, script)
		if got != want {
			t.Errorf("error(%q):\n  go   = %q\n  ruby = %q", in, got, want)
		}
	}
}

// TestOracleNtop checks IPAddr.ntop against MRI for the success paths and for
// the two distinct failure modes whose precedence the port must preserve: a
// non-BINARY encoding (InvalidAddressError, checked first) versus a bad length
// under BINARY (AddressFamilyError).
func TestOracleNtop(t *testing.T) {
	bin := rubyBin(t)

	type ntCase struct {
		bytes string // raw bytes of the argument
		enc   string // Ruby encoding name
	}
	cases := []ntCase{
		{"\x01\x02\x03\x04", "ASCII-8BIT"}, // 4 bytes BINARY -> IPv4
		{"\x20\x01\x0d\xb8\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x01", "ASCII-8BIT"}, // 16 bytes BINARY -> IPv6
		{"xy", "ASCII-8BIT"},             // bad length BINARY -> AddressFamilyError
		{"xy", "UTF-8"},                  // non-BINARY -> InvalidAddressError (precedence)
		{"\x01\x02\x03\x04", "US-ASCII"}, // valid length but non-BINARY -> InvalidAddressError
	}
	for _, c := range cases {
		got := ntopResult(NtopString(c.bytes, c.enc))
		// Build the Ruby argument with the requested encoding, byte-for-byte.
		var rb strings.Builder
		rb.WriteByte('"')
		for i := 0; i < len(c.bytes); i++ {
			rb.WriteString("\\x")
			rb.WriteString(hexByte(c.bytes[i]))
		}
		rb.WriteString("\".dup.force_encoding(")
		rb.WriteString(rbStr(c.enc))
		rb.WriteByte(')')
		script := "arg = " + rb.String() + "\n" +
			"begin; print IPAddr.ntop(arg); rescue => e; print \"#{e.class}: #{e.message}\"; end"
		want := rubyEval(t, bin, script)
		if got != want {
			t.Errorf("ntop(%q, %s):\n  go   = %q\n  ruby = %q", c.bytes, c.enc, got, want)
		}
	}
}

// ntopResult renders an NtopString result the same way the Ruby script prints it:
// the readable address on success, or "<class>: <message>" on failure.
func ntopResult(s string, err error) string {
	if err == nil {
		return s
	}
	return errClass(err) + ": " + err.Error()
}

// hexByte renders b as a two-digit lowercase hex string.
func hexByte(b byte) string {
	const hexdigits = "0123456789abcdef"
	return string([]byte{hexdigits[b>>4], hexdigits[b&0xf]})
}

// errClass renders the IPAddr:: error class name MRI would report.
func errClass(err error) string {
	switch err.(type) {
	case *InvalidPrefixError:
		return "IPAddr::InvalidPrefixError"
	case *InvalidAddressError:
		return "IPAddr::InvalidAddressError"
	case *AddressFamilyError:
		return "IPAddr::AddressFamilyError"
	default:
		return "IPAddr::Error"
	}
}

func b2s(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }

// rbStr renders a Go string as a Ruby double-quoted literal for embedding in a
// `-e` script (only the corpus characters need escaping).
func rbStr(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			sb.WriteByte('\\')
		}
		sb.WriteRune(r)
	}
	sb.WriteByte('"')
	return sb.String()
}
