package iptablesConverter

import (
	"iptablesConverter/iptables"
	"iptablesConverter/nftables"
	"iptablesConverter/packetfilter"
	"log"
)

func ReadIPTables(path string) iptables.Iptables {
	var ipt iptables.Iptables
	var pe iptables.ParseError
	ipt, pe = iptables.Read(path)
	if pe.Msg != "" {
		log.Panicln("Parse error at line ", pe.Line, pe.Msg, pe.Err)
	}
	return ipt
}

func ReadNFTables(path string) (nftables.Nftables, error) {
	return nftables.Read(path)
}

func ReadPfilters(path string) (packetfilter.Pfilter, error) {
	return packetfilter.Read(path)
}

func ConvertToNFTables(ipt iptables.Iptables) nftables.Nftables {
	// first, create all the tables (unlike Nftables, iptables is fixed to known tables only)
	var nft nftables.Nftables
	nft.AddTable(nftables.CAddressFamilyIP, "filter")
	nft.AddTable(nftables.CAddressFamilyIP6, "filter")
	nft.AddTable(nftables.CAddressFamilyIP, "mangle")
	nft.AddTable(nftables.CAddressFamilyIP6, "mangle")
	nft.AddTable(nftables.CAddressFamilyIP, "nat")
	nft.AddTable(nftables.CAddressFamilyIP6, "nat")
	nft.AddTable(nftables.CAddressFamilyIP, "raw")
	nft.AddTable(nftables.CAddressFamilyIP6, "raw")
	nft.AddTable(nftables.CAddressFamilyIP, "security")
	nft.AddTable(nftables.CAddressFamilyIP6, "security")

	for _, r := range ipt.Filter.BuiltInInput {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, r := range ipt.Filter.BuiltInOutput {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, r := range ipt.Filter.BuiltInForward {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, u := range ipt.Filter.Userdefined {
		log.Printf("# === %s\n", u.Name)
		for _, r := range u.Rules {
			log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
		}
	}

	for _, r := range ipt.Mangle.BuiltInPrerouting {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, r := range ipt.Mangle.BuiltInInput {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, r := range ipt.Mangle.BuiltInOutput {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, r := range ipt.Mangle.BuiltInForward {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, r := range ipt.Mangle.BuiltInPostrouting {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, u := range ipt.Mangle.Userdefined {
		log.Printf("# === %s\n", u.Name)
		for _, r := range u.Rules {
			log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
		}
	}

	for _, r := range ipt.Nat.BuiltInPrerouting {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, r := range ipt.Nat.BuiltInOutput {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, r := range ipt.Nat.BuiltInPostrouting {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, u := range ipt.Nat.Userdefined {
		log.Printf("# === %s\n", u.Name)
		for _, r := range u.Rules {
			log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
		}
	}

	for _, r := range ipt.Raw.BuiltInPrerouting {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, r := range ipt.Raw.BuiltInOutput {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, u := range ipt.Raw.Userdefined {
		log.Printf("# === %s\n", u.Name)
		for _, r := range u.Rules {
			log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
		}
	}

	for _, r := range ipt.Security.BuiltInInput {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, r := range ipt.Security.BuiltInOutput {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, r := range ipt.Security.BuiltInForward {
		log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
	}
	for _, u := range ipt.Security.Userdefined {
		log.Printf("# === %s\n", u.Name)
		for _, r := range u.Rules {
			log.Printf("%d: Processing '%s'\n", r.Line, r.Rule)
		}
	}
	return nft
}
