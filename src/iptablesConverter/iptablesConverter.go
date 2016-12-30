package iptablesConverter

import (
	"iptablesConverter/iptables"
	"iptablesConverter/nftables"
	"iptablesConverter/packetfilter"
	"log"
)

func ReadIPTables(path string) iptables.Iptables {
	ipt, err := iptables.Read(path)
	if err.msg != "" {
		log.Panicln("Parse error at line ", err.line, err.msg, err.err)
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
