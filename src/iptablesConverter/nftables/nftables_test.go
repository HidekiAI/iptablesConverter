package nftables

import "testing"
import "strconv"

func FindTableSuccess(t *testing.T) {
	m := make(map[TUniqueTableName]TTable)
	m["ip.filter"] = TTable{Name: "filter", Family: CAddressFamilyIP}
	nft := Nftables{Tables: m}
	if found, _ := nft.FindTable(CAddressFamilyIP, "filter"); found == false {
		t.Fail()
	}
}

func FindTableNotFound(t *testing.T) {
	m := make(map[TUniqueTableName]TTable)
	m["ip6.filter"] = TTable{Name: "filter", Family: CAddressFamilyIP6}
	nft := Nftables{Tables: m}
	// Should not find "filter" for it's not unique (i.e. "ip.filter" vs "ip6.filter")
	if found, _ := nft.FindTable(CAddressFamilyIP, "filter"); found {
		t.Fail()
	}
}

func AddTableFilter(t *testing.T) {
	var nft Nftables
	if found := nft.AddTable(CAddressFamilyIP6, "filter"); found {
		t.Errorf("Found table in an empty Nftables\n")
		t.Fail()
	}
}

func TestStripComment(t *testing.T) {
	s := `this line has 'quoted #comments' followed by "double-quoted #comment's with sinqle quote in it" here comes the hash:`
	swc := s + ` # <-- and here's the end`
	ss := stripComment(swc)
	t.Logf("Original: '%s'\n", swc)
	t.Logf("Stripped: '%s'\n", ss)
	t.Logf("Expected: '%s'\n", s)
	if ss != s {
		t.Fail()
	}
}

func printTextBlockRecursive(t *testing.T, tsPtr *TTextStatement, tabs string) {
	if tsPtr != nil {
		outStr := tabs
		for it, t := range tsPtr.Tokens {
			outStr += "(" + strconv.Itoa(it) + ",'" + t + "'),"
		}
		t.Log(outStr)
		// Now dump TTextSTatement.SubStatement[]
		for _, ss := range tsPtr.SubStatement {
			printTextBlockRecursive(t, ss, tabs+"\t")
		}
	}
}

func TestTextBlock(t *testing.T) {
	s := `
# filter
table ip filter {
	chain input { # input chain
		type filter hook input priority 0; policy drop;	# default policy to drop
			ct state invalid counter drop comment "drop invalid packets"
			ct state {established, related} counter accept comment "accept all connections related to connections made by us"
			iifname lo accept comment "accept loopback"
			iifname != lo ip daddr 127.0.0.1/8 counter drop comment "don't worry, #comments cannot have double quotes inside it"
			ip protocol icmp counter accept comment "comment has ' and # in it"
			tcp dport 22 counter accept comment "accept ssh"
			counter comment "count dropped packets"
	}

	chain output {
		type filter hook output priority 0; policy accept;		counter comment "comment has a ' in it";
		;
	}

	# using '\' to do continuations
	chain forward {
		type filter hook forward \
			priority 0; policy drop;
		counter comment "count dropped packets";
		{some made up { nested statement } in one line}
	}

	# all in one line, with ';' right before '}' and adding {} to fool the parser }
	chain nat{type filter hook nat priority 0;policy drop;}
}`

	tsList := MakeStatements(s)
	for i, ts := range tsList {
		t.Logf("Statement #%d", i)
		printTextBlockRecursive(t, &ts, "\t")
	}
}
