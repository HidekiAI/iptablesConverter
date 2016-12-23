package main

import (
	"iptablesConverter/iptables"
	"iptablesConverter/nftables"
	"iptablesConverter/packetfilter"
)

func ParseToNftables(ipt iptables.Iptables) nftables.Nftables {
	ret := nftables.Nftables{
		X: 0,
		Y: 0,
	}
	return ret
}

func ParseToPf(ipt iptables.Iptables) packetfilter.Pfilter {
	ret := packetfilter.Pfilter{
		X: 0,
		Y: 0,
	}
	return ret
}

func main() {
}
