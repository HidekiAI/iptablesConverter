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

func ReadNFTables(path string) nftables.Nftables {
	nft := nftables.Read(path)
	return nft
}

func ReadPfilters(path string) packetfilter.Pfilter {
	pf := packetfilter.Read(path)
	return pf
}
