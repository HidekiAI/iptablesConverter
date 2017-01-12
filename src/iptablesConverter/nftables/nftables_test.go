package nftables

import "testing"

//import "strconv"
import "fmt"

func TestAddTableSuccess(t *testing.T) {
	var nft Nftables
	addedT := nft.AddTable(CAddressFamilyIP, "filter")
	if addedT == nil {
		t.Fail()
	}
	found := nft.FindTable(CAddressFamilyIP, "filter")
	if found == nil {
		t.Fail()
	}
}

func TestAddTableNotFound(t *testing.T) {
	var nft Nftables
	addedT := nft.AddTable(CAddressFamilyIP6, "filter")
	if addedT == nil {
		t.Fail()
	}
	// Should not find "filter" for it's not unique (i.e. "ip.filter" vs "ip6.filter")
	found := nft.FindTable(CAddressFamilyIP, "filter")
	if found != nil {
		t.Fail()
	}
}

func TestFindTableNoAdd(t *testing.T) {
	var nft Nftables
	found := nft.FindTable(CAddressFamilyIP6, "filter")
	if found != nil {
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

func testPrintTextBlockRecursive(t *testing.T, tsPtr *TTextStatement, ti int, si int) {
	const tabs = "|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|"
	if tsPtr != nil {
		outStr := fmt.Sprintf("%3d:(%16p:%16p)%s", si, tsPtr.Parent, tsPtr, tabs[:ti])
		if len(tsPtr.Tokens) > 0 {
			for _, t := range tsPtr.Tokens {
				outStr += t + " "
			}
		}
		t.Log(outStr)

		// Now dump TTextSTatement.SubStatement[]
		if len(tsPtr.SubStatement) > 0 {
			for _, ss := range tsPtr.SubStatement {
				testPrintTextBlockRecursive(t, ss, ti+1, si)
			}
		}
	}
}

func TestTextBlock(t *testing.T) {
	s := `
# filter
table ip filter {
	chain input { # input chain
		type filter hook input priority 0; policy drop;# sticky semi-colon and comment edge-case
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
}
# ip6 filter
table ip6 filter {
}`

	tsList := MakeStatements(s)
	for i, ts := range tsList {
		testPrintTextBlockRecursive(t, ts, 0, i)
	}
}

func TestDeserializeFromFile(t *testing.T) {
	path := "nft.rules"
	nft := Read(path)
	t.Logf("%+v", nft)
	// assume the rules files only has two tables (ip and ip6)
	if len(nft.Tables) != 2 {
		t.Fail()
	}
}
