# Introductions
This project is *not* to emulate and/or substitude for [iptables-translate](https://wiki.nftables.org/wiki-nftables/index.php/Moving_from_iptables_to_nftables).
It originally started as a desire to self-teach golang, and I have been in a need to upgrade several of
my iptables.rule (and ip6tables.rule) files for each server that have specific rules and are getting
quite large to manage.

The project are broken down into few parts:
- Iptables parser/deserializer from the iptable/ip6table rule files
- Nftables serializer from Iptables (as an object)
- Possibly in the future, also would like PF as well

Goals and intentions have been to not use libnftl, libmnl, etc because of few undesirable reasons associated
to cgo, which you may be able to use your favorite search engines to speculate.
But mainly because I wanted to make sure it can be built on any \*NIX which does not have the capabilities
to build the associated lib files (i.e. bulding iptable lib files in BSD?).



# Examples

# TODO
- [x] Reading and deserializing iptables.rule and ip6tables.rule files into Iptables object
- [ ] Nftable serialization from Iptables package
- [ ] PF serialization from Iptables package
- [ ] Unit-test for each packages
- [ ] This README.md file

# Caveats
Currently, less used iptables match extensions (and its options) throw a log.Panic() and will be
implemented as the needs occur.
