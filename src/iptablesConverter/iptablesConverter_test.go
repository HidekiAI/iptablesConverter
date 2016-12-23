package iptablesConverter

import "testing"

func ReadIPTables4Test(testing *testing.T) {
	ipt := ReadIPTables("iptables4.conf")
}

func ReadIPTables6Test(testing *testing.T) {
	ipt := ReadIPTables("iptables6.conf")
}

func ReadNFTablesTest(testing *testing.T) {
	nft := ReadNFTables("nf4.conf")
}

func ReadPfiltersTest(testing *testing.T) {
	pft := ReadPfilters("pf.conf")
}
