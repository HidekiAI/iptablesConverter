package iptablesConverter

import "testing"

func ReadIPTables4Test(t *testing.T) {
	f := "/etc/iptables.rules"
	t.Log("Reading " + f)
	ipt := ReadIPTables(f)
	t.Log(ipt)
}

func ReadIPTables6Test(t *testing.T) {
	f := "/etc/ip6tables.rules"
	t.Log("Reading " + f)
	ipt := ReadIPTables(f)
	t.Log(ipt)
}

func ReadNFTablesTest(t *testing.T) {
	nft := ReadNFTables("nf4.rules")
	t.Log(nft)
}

func ReadPfiltersTest(t *testing.T) {
	pft := ReadPfilters("pf4.rules")
	t.Log(pft)
}
