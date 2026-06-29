<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-ipaddr/brand/main/social/go-ruby-ipaddr-ipaddr.png" alt="go-ruby-ipaddr/ipaddr" width="720"></p>

# ipaddr — go-ruby-ipaddr

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-ipaddr.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of Ruby's [`ipaddr`](https://docs.ruby-lang.org/en/master/IPAddr.html)
standard library** — MRI 4.0.5's `IPAddr` class. It models an IP address together
with a netmask (IPv4 or IPv6) and reproduces MRI's parsing, masking, string
formatting, set predicates, bitwise operators and comparison semantics
byte-for-byte, **without any Ruby runtime**.

It is the `IPAddr` backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but is a
**standalone, reusable** module — a sibling of
[go-ruby-regexp](https://github.com/go-ruby-regexp/regexp) (the Onigmo engine),
[go-ruby-erb](https://github.com/go-ruby-erb/erb) (the ERB compiler) and
[go-ruby-yaml](https://github.com/go-ruby-yaml/yaml) (the Psych port).

> **Why it's deterministic.** Parsing, masking and formatting IP addresses is a
> pure, interpreter-independent computation, so it lives here as pure Go. The
> arithmetic is carried in `math/big.Int`, so the full 128-bit IPv6 space and
> MRI's unbounded-integer behaviour (e.g. `IPAddr.new("255.255.255.255").succ`
> raising `invalid address: 4294967296`) are matched exactly. Go's `net/netip`
> could supply the address math, but MRI's `to_s` collapsing rules, `inspect`
> form, error classes and masking edge-cases are reproduced directly so the API
> is MRI-faithful rather than netip-faithful.

## Features

Faithful port of `IPAddr`, validated against the `ruby` binary on every platform:

- **Parsing** — `"a.b.c.d"`, `"addr/prefixlen"`, `"addr/netmask"`, bracketed
  IPv6 (`"[::1]/64"`), `%zone` identifiers, embedded IPv4 tails
  (`"::ffff:1.2.3.4"`, `"1:2:3:4:5:6:1.2.3.4"`), with MRI's ambiguous-zero-fill
  and out-of-range octet rejections.
- **Formatting** — `to_s` (compact, with MRI's exact zero-run collapsing and the
  `::a.b.c.d` / `::ffff:a.b.c.d` rewrites), `to_string` (canonical expanded),
  `cidr`, `inspect` (`#<IPAddr: IPv4:…/mask>`), `netmask`.
- **Masking** — `mask(prefixlen|netmask)`, `prefix` / `prefix=`, masked
  construction; non-contiguous-netmask and leading-zero-prefix rejection.
- **Set membership** — `include?` / `===`, `to_range`, plus an idiomatic `Each`
  over the range.
- **Bitwise** — `&`, `|`, `~`, `+`, `-`, `succ`, and `Xor` (the natural
  completion of the `&`/`|` set), all coercing strings / integers / `IPAddr`.
- **Comparison** — `<=>` (Comparable), `==`, `eql?`-style `Hash`.
- **Predicates** — `ipv4?`, `ipv6?`, `loopback?`, `private?`, `link_local?`,
  `multicast?`, `ipv4_mapped?`, `ipv4_compat?`.
- **Conversions** — `native`, `ipv4_mapped`, `ipv4_compat`, `hton`, `ntop`,
  `new_ntoh`, `family`, `to_i`.
- **Errors** — `InvalidAddressError`, `InvalidPrefixError`, `AddressFamilyError`
  (under a base `Error`), with MRI's exact messages.

CGO-free, dependency-free, **100% test coverage**, `gofmt` + `go vet` clean, and
green across the six 64-bit Go targets (amd64, arm64, riscv64, loong64, ppc64le,
s390x) and three OSes (Linux, macOS, Windows).

## Install

```sh
go get github.com/go-ruby-ipaddr/ipaddr
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/go-ruby-ipaddr/ipaddr"
)

func main() {
	net, _ := ipaddr.New("192.168.1.5/24")
	fmt.Println(net.ToS())   // 192.168.1.0   (masked, like MRI)
	fmt.Println(net.Cidr())  // 192.168.1.0/24

	in, _ := net.Include("192.168.1.99")
	fmt.Println(in)          // true

	v6, _ := ipaddr.New("::1")
	fmt.Println(v6.Ipv6())   // true

	merged, _ := mustOr(ipaddr.New("10.0.0.0/8")).Or(0x00010203)
	fmt.Println(merged.ToS()) // 10.1.2.3

	lo, hi, _ := net.ToRange()
	fmt.Println(lo.ToS(), hi.ToS()) // 192.168.1.0 192.168.1.255
}

func mustOr(ip *ipaddr.IPAddr, _ error) *ipaddr.IPAddr { return ip }
```

## API

```go
// Construction.
func New(s string) (*IPAddr, error)                       // IPAddr.new(s)
func NewFamily(s string, family Family) (*IPAddr, error)   // IPAddr.new(s, family)
func NewFromInt(addr *big.Int, family Family) (*IPAddr, error)
func NewNtoh(addr []byte) (*IPAddr, error)                 // IPAddr.new_ntoh
func Ntop(addr []byte) (string, error)                     // IPAddr.ntop

// Strings.
func (ip *IPAddr) ToS() string        // to_s   (compact)
func (ip *IPAddr) ToString() string   // to_string (canonical)
func (ip *IPAddr) Cidr() string       // cidr
func (ip *IPAddr) Inspect() string    // inspect
func (ip *IPAddr) Netmask() string    // netmask

// Masking / prefix.
func (ip *IPAddr) Mask(prefixlen string) (*IPAddr, error) // mask("24"|"255.255.255.0")
func (ip *IPAddr) MaskLen(prefixlen int) (*IPAddr, error)
func (ip *IPAddr) Prefix() int
func (ip *IPAddr) SetPrefix(prefix int) (*IPAddr, error)  // prefix=

// Membership / range.
func (ip *IPAddr) Include(other any) (bool, error)        // include? / ===
func (ip *IPAddr) ToRange() (lo, hi *IPAddr, err error)   // to_range
func (ip *IPAddr) Each(fn func(*IPAddr) error) error

// Bitwise / arithmetic (other: *IPAddr | string | int | int64 | uint64 | *big.Int).
func (ip *IPAddr) And(other any) (*IPAddr, error)         // &
func (ip *IPAddr) Or(other any) (*IPAddr, error)          // |
func (ip *IPAddr) Xor(other any) (*IPAddr, error)         // ^ (extension)
func (ip *IPAddr) Not() (*IPAddr, error)                  // ~
func (ip *IPAddr) Add(offset int64) (*IPAddr, error)      // +
func (ip *IPAddr) Sub(offset int64) (*IPAddr, error)      // -
func (ip *IPAddr) Succ() (*IPAddr, error)                 // succ

// Comparison.
func (ip *IPAddr) Cmp(other any) (int, bool)              // <=>  (ok=false ~> nil)
func (ip *IPAddr) Eql(other any) bool                     // ==
func (ip *IPAddr) Hash() uint64

// Predicates.
func (ip *IPAddr) Ipv4() bool
func (ip *IPAddr) Ipv6() bool
func (ip *IPAddr) Loopback() bool
func (ip *IPAddr) Private() bool
func (ip *IPAddr) LinkLocal() bool
func (ip *IPAddr) Multicast() bool        // extension: MRI 4.0.5 has no multicast?
func (ip *IPAddr) IsIpv4Mapped() bool     // ipv4_mapped?
func (ip *IPAddr) IsIpv4Compat() bool     // ipv4_compat?

// Conversions.
func (ip *IPAddr) Native() (*IPAddr, error)
func (ip *IPAddr) Ipv4Mapped() (*IPAddr, error)
func (ip *IPAddr) Ipv4Compat() (*IPAddr, error)
func (ip *IPAddr) HtonString() ([]byte, error)  // hton
func (ip *IPAddr) Family() Family
func (ip *IPAddr) ToI() *big.Int

// Errors (Error is the base; InvalidPrefixError is an InvalidAddressError in MRI).
type Error struct{ Msg string }
type InvalidAddressError struct{ Msg string }
type InvalidPrefixError struct{ Msg string }
type AddressFamilyError struct{ Msg string }
```

## Notes on parity

- **`multicast?` and `^`** do not exist on MRI 4.0.5's `IPAddr`; `Multicast` and
  `Xor` are provided here as natural extensions and are flagged as such above.
- **`Each`** has no MRI counterpart either (MRI's `IPAddr` is not `Enumerable`);
  it is the idiomatic Go iteration over `to_range` that the host binds to a block.
- **`Family()`** returns `AFInet` (2) / `AFInet6` (10). MRI stores the host's
  `Socket::AF_INET6`, whose integer varies by OS (10 on Linux, 30 on the BSDs);
  use `Ipv4()` / `Ipv6()` for portable checks.
- **`Hash()`** matches MRI's IPv4/IPv6 parity bit; the upper bits are a stable
  in-process mix (MRI's `Array#hash` is interpreter-specific), so it is for
  in-process `Hash`/`Set` keying, not cross-runtime equality.

## Tests & coverage

The suite pairs deterministic, ruby-free tests (which alone hold coverage at
**100%**, so the qemu cross-arch and Windows lanes pass the gate) with a
**differential MRI oracle**: a wide corpus is parsed and formatted here and the
results compared to the system `ruby -ripaddr` (`to_s` / `to_string` / `cidr` /
`inspect`, the predicates, the operators, `to_range`, the conversions, and the
error class + message). The oracle scripts `$stdout.binmode` / `$stdin.binmode`
so Windows text-mode never pollutes the bytes, gate on `RUBY_VERSION >= "4.0"`,
and skip themselves where `ruby` is absent.

```sh
COVERPKG=$(go list ./... | paste -sd, -)
go test -race -coverpkg="$COVERPKG" -coverprofile=cover.out ./...
go tool cover -func=cover.out | tail -1   # 100.0%
```

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright the go-ruby-ipaddr/ipaddr authors.
