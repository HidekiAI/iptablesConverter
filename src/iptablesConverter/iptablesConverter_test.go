package iptablesConverter

import "testing"

func ReadIPTables4Test(t *testing.T) {
	f := "iptables.rules"
	t.Log("Reading " + f)
	ipt := ReadIPTables(f)
	t.Log(ipt)
}

func ReadIPTables6Test(t *testing.T) {
	f := "ip6tables.rules"
	t.Log("Reading " + f)
	ipt := ReadIPTables(f)
	t.Log(ipt)
}

func ReadNFTablesTest(t *testing.T) {
	nft, err := ReadNFTables("nf4.rules")
	t.Log(nft)
	if err != nil {
		t.Fail()
	}
}

func ReadPfiltersTest(t *testing.T) {
	pft, err := ReadPfilters("pf4.rules")
	t.Log(pft)
	if err != nil {
		t.Fail()
	}
}
