# Ruby examples

Pure-Ruby examples of the `ipaddr` standard library — the Ruby face of this
library. They run under [go-embedded-ruby](https://github.com/go-embedded-ruby/ruby)
(rbgo), which binds `require "ipaddr"` to the pure-Go `IPAddr` in this repo:

```
rbgo examples/ipaddr_usage.rb
```

| File | Shows |
| --- | --- |
| [`ipaddr_usage.rb`](ipaddr_usage.rb) | Parsing (`addr/prefixlen`), `to_s`/`inspect`/`cidr`/`prefix`, set membership (`include?`, `===`, `to_range`), predicates (`ipv4?`, `private?`), integer/bitwise views (`to_i`, `&`, `succ`), and IPv6. |
