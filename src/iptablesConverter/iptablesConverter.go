package iptablesConverter

import (
	"iptablesConverter/iptables"
	"iptablesConverter/nftables"
	"iptablesConverter/packetfilter"
)

func ReadIPTables(path string) iptables.Iptables {
	ipt := iptables.Read(path)
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
