package main

import (
	"iptablesConverter/iptables"
	"iptablesConverter/nftables"
	"iptablesConverter/packetfilter"
)

func ParseToNftables(ipt iptables.Iptables) nftables.Nftables {
	ret := nftables.Nftables{}
	return ret
}

func ParseToPf(ipt iptables.Iptables) packetfilter.Pfilter {
	ret := packetfilter.Pfilter{}
	return ret
}

func main() {
}
