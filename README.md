# Introductions
This project is *not* to emulate and/or substitute for [iptables-translate](https://wiki.nftables.org/wiki-nftables/index.php/Moving_from_iptables_to_nftables).
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
TODO: Use more practical examples, not snippets for test file
```
func TestDeserializeFromFile(t *testing.T) {
	path := "nft.rules"
	nft := Read(path)

	t.Logf("%+v", nft)
	// assume the rules files only has two tables (ip and ip6)
	if len(nft.Tables) != 2 {
		t.Fail()
	}
}
```

# TODO
- [x] Reading and deserializing iptables.rule and ip6tables.rule files into Iptables object
- [x] Parse Nftable rule files
- [ ] Deserialization of nft.rules files to Nftable object
- [ ] Nftable serialization from nft.rules file or Iptables package
- [ ] PF serialization from Iptables package
- [ ] Unit-test for each packages
- [ ] This README.md file
- [ ] Create build rules for Gentoo (ebuild) and Makefile for 'make install' so that generated binaries can be installed in 'bin' (or 'sbin'?) paths

# Caveats
Currently, less used iptables match extensions (and its options) throw a log.Panic() and will be
implemented as the needs occur.
