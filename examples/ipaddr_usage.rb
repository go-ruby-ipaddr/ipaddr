# frozen_string_literal: true
#
# Primary usage of the `ipaddr` standard library under go-embedded-ruby (rbgo).
# IPAddr models an IP address together with a netmask (IPv4 or IPv6).

require "ipaddr"

# Parse an address with a prefix length. to_s is compact; inspect shows the mask.
net = IPAddr.new("192.168.1.0/24")
puts net.to_s        # => 192.168.1.0
puts net.inspect     # => #<IPAddr: IPv4:192.168.1.0/255.255.255.0>
puts net.cidr        # => 192.168.1.0/24
puts net.prefix      # => 24

# Set membership: include? and === test whether an address falls in the range.
puts net.include?("192.168.1.42")          # => true
puts(net === "192.168.1.42")               # => true
puts net.to_range.to_s                     # => 192.168.1.0..192.168.1.255

# Predicates and integer/bitwise views of a single host address.
host = IPAddr.new("192.168.1.42")
puts host.ipv4?                            # => true
puts host.private?                         # => true
puts host.to_i                             # => 3232235818
puts (host & "255.255.255.0").to_s         # => 192.168.1.0
puts host.succ.to_s                        # => 192.168.1.43

# IPv6 works the same way, with MRI-faithful zero-run collapsing.
v6 = IPAddr.new("2001:db8::1")
puts v6.to_s                               # => 2001:db8::1
puts v6.ipv6?                              # => true
puts IPAddr.new("::1").loopback?           # => true
